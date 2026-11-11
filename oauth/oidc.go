package oauth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/disaster37/go-auth/crypto"
	"github.com/disaster37/go-auth/domain"
	"github.com/disaster37/go-auth/jwt"
	"github.com/disaster37/go-auth/observ"
	"github.com/disaster37/go-auth/password"
	"github.com/disaster37/go-auth/store"
)

// OIDCConfig configures an OIDCOAuthService.
type OIDCConfig struct {
	ProviderID           string
	ClientID             string
	ClientSecret         string
	RedirectURL          string
	IssuerURL            string
	AllowInsecureIssuer  bool
	AllowedEndpoints     []string
	Scopes               []string
	UsernameClaim        string
	GroupsClaim          string
	RequireEmailVerified bool
	AllowedGroups        []string
	AllowedOrgs          []string // deprecated alias merged with AllowedGroups
	AdminGroups          []string
	DefaultGroup         string
	CACertPath           string
	RequireNonce         bool
	EnablePKCE           bool
	AutoCreateUser       bool
	// AuthEpoch optionally supplies the current cluster-wide AuthEpoch so that
	// OAuth-issued JWTs carry the same global revocation counter as the rest of
	// the system. When nil, tokens are issued with epoch 0.
	AuthEpoch func() int64
}

// OIDCOAuthService implements the generic OIDC authorization-code login flow.
type OIDCOAuthService struct {
	cfg           OIDCConfig
	scopes        []string
	usernameClaim string
	groupsClaim   string
	issuerURL     string
	mapper        *GroupMapper
	lc            loginContext
	sealer        crypto.Sealer
	httpClient    *http.Client
	isLeader      func() bool
	logger        observ.Logger

	mu     sync.Mutex
	cached *oidc.Provider
}

// NewOIDCOAuthService returns an OIDCOAuthService. The issuer URL is
// trailing-slash-normalized; "openid" and "offline_access" are appended to
// scopes when missing; empty claim names fall back to
// preferred_username/groups.
func NewOIDCOAuthService(
	cfg OIDCConfig,
	mapper *GroupMapper,
	users *password.Service,
	userStore store.UserStore,
	groups store.GroupStore,
	jwtSvc *jwt.Service,
	sealer crypto.Sealer,
	httpClient *http.Client,
	isLeader func() bool,
	logger observ.Logger,
) (*OIDCOAuthService, error) {
	if err := validateIssuerURL(cfg.IssuerURL, cfg.AllowInsecureIssuer); err != nil {
		return nil, err
	}
	if logger == nil {
		logger = observ.NewNoopLogger()
	}
	if httpClient == nil {
		httpClient, _ = NewOAuthHTTPClient("", DefaultHTTPTimeout)
	}
	usernameClaim := cfg.UsernameClaim
	if usernameClaim == "" {
		usernameClaim = "preferred_username"
	}
	groupsClaim := cfg.GroupsClaim
	if groupsClaim == "" {
		groupsClaim = "groups"
	}
	return &OIDCOAuthService{
		cfg:           cfg,
		scopes:        normalizeScopes(cfg.Scopes),
		usernameClaim: usernameClaim,
		groupsClaim:   groupsClaim,
		issuerURL:     strings.TrimRight(cfg.IssuerURL, "/"),
		mapper:        mapper,
		lc: loginContext{
			users:        users,
			userStore:    userStore,
			groups:       groups,
			jwt:          jwtSvc,
			sealer:       sealer,
			logger:       logger,
			adminGroups:  cfg.AdminGroups,
			defaultGroup: cfg.DefaultGroup,
			autoCreate:   cfg.AutoCreateUser,
			epoch:        cfg.AuthEpoch,
		},
		sealer:     sealer,
		httpClient: httpClient,
		isLeader:   isLeader,
		logger:     logger,
	}, nil
}

// Name returns the provider ID.
func (s *OIDCOAuthService) Name() string { return s.cfg.ProviderID }

func normalizeScopes(scopes []string) []string {
	out := make([]string, 0, len(scopes)+2)
	out = append(out, scopes...)
	hasOpenID, hasOffline := false, false
	for _, sc := range out {
		if sc == "openid" {
			hasOpenID = true
		}
		if sc == "offline_access" {
			hasOffline = true
		}
	}
	if !hasOpenID {
		out = append(out, "openid")
	}
	if !hasOffline {
		out = append(out, "offline_access")
	}
	return out
}

func validateIssuerURL(issuerURL string, allowInsecure bool) error {
	u, err := url.Parse(issuerURL)
	if err != nil {
		return fmt.Errorf("parse issuer_url: %w", err)
	}
	if u.Scheme != "https" && !allowInsecure && !isLoopbackHost(u.Hostname()) {
		return fmt.Errorf("issuer_url must use https (set allow_insecure_issuer only for trusted loopback/dev providers): %w", domain.ErrValidation)
	}
	return nil
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (s *OIDCOAuthService) leader() bool {
	return s.isLeader == nil || s.isLeader()
}

func (s *OIDCOAuthService) oauth2Config(ep oauth2.Endpoint) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     s.cfg.ClientID,
		ClientSecret: s.cfg.ClientSecret,
		RedirectURL:  s.cfg.RedirectURL,
		Endpoint:     ep,
		Scopes:       s.scopes,
	}
}

func (s *OIDCOAuthService) discover(ctx context.Context) (*oidc.Provider, error) {
	s.mu.Lock()
	if s.cached != nil {
		p := s.cached
		s.mu.Unlock()
		return p, nil
	}
	s.mu.Unlock()

	discoverCtx := ctx
	if s.httpClient != nil {
		discoverCtx = oidc.ClientContext(ctx, s.httpClient)
	}
	p, err := oidc.NewProvider(discoverCtx, s.issuerURL)
	if err != nil {
		s.logger.Warn("oidc: provider discovery failed", map[string]any{"issuer": s.issuerURL})
		return nil, fmt.Errorf("oidc: discover provider: %w", err)
	}
	if err := s.validateEndpoints(p); err != nil {
		return nil, err
	}
	s.mu.Lock()
	if s.cached == nil {
		s.cached = p
	} else {
		p = s.cached
	}
	s.mu.Unlock()
	return p, nil
}

// validateEndpoints enforces the allowed_endpoints allowlist against the
// discovered token and userinfo endpoints.
func (s *OIDCOAuthService) validateEndpoints(p *oidc.Provider) error {
	if len(s.cfg.AllowedEndpoints) == 0 {
		return nil
	}
	var claims struct {
		TokenEndpoint    string `json:"token_endpoint"`
		UserinfoEndpoint string `json:"userinfo_endpoint"`
	}
	if err := p.Claims(&claims); err != nil {
		return fmt.Errorf("oidc: read discovery claims: %w", err)
	}
	for _, ep := range []string{claims.TokenEndpoint, claims.UserinfoEndpoint} {
		if ep == "" {
			continue
		}
		if !endpointAllowed(s.cfg.AllowedEndpoints, ep) {
			return fmt.Errorf("oidc: discovered endpoint %q is outside allowed_endpoints: %w", ep, domain.ErrValidation)
		}
	}
	return nil
}

func endpointAllowed(allowed []string, endpoint string) bool {
	u, err := url.Parse(endpoint)
	if err != nil {
		return false
	}
	for _, a := range allowed {
		au, err := url.Parse(a)
		if err != nil {
			continue
		}
		if au.Host == u.Host && strings.HasPrefix(u.Path, au.Path) {
			return true
		}
	}
	return false
}

// LoginURL returns the OIDC authorize URL. Discovery is bounded by
// DefaultDiscoveryTimeout; a discovery failure yields an empty URL.
func (s *OIDCOAuthService) LoginURL(params AuthorizeParams) string {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultDiscoveryTimeout)
	defer cancel()
	p, err := s.discover(ctx)
	if err != nil {
		return ""
	}
	opts := make([]oauth2.AuthCodeOption, 0, 3)
	if params.CodeChallenge != "" {
		opts = append(opts, oauth2.SetAuthURLParam("code_challenge", params.CodeChallenge), oauth2.SetAuthURLParam("code_challenge_method", "S256"))
	}
	if params.Nonce != "" {
		opts = append(opts, oauth2.SetAuthURLParam("nonce", params.Nonce))
	}
	return s.oauth2Config(p.Endpoint()).AuthCodeURL(params.State, opts...)
}

// Complete exchanges the code for tokens, verifies the ID token, extracts the
// sub/username/groups claims, enforces the allowlist, resolves the local user,
// and issues a JWT pair.
func (s *OIDCOAuthService) Complete(ctx context.Context, params CompleteParams) (access, refresh string, u *domain.User, err error) {
	if s.httpClient != nil {
		ctx = oidc.ClientContext(ctx, s.httpClient)
	}
	p, err := s.discover(ctx)
	if err != nil {
		return "", "", nil, err
	}

	exchangeOpts := make([]oauth2.AuthCodeOption, 0, 1)
	if params.CodeVerifier != "" {
		exchangeOpts = append(exchangeOpts, oauth2.VerifierOption(params.CodeVerifier))
	}
	tok, err := s.oauth2Config(p.Endpoint()).Exchange(ctx, params.Code, exchangeOpts...)
	if err != nil {
		return "", "", nil, fmt.Errorf("oidc: exchange code: %w", err)
	}

	rawIDToken, _ := tok.Extra("id_token").(string)
	if rawIDToken == "" {
		return "", "", nil, fmt.Errorf("oidc: no id_token returned")
	}
	idToken, err := p.Verifier(&oidc.Config{ClientID: s.cfg.ClientID}).Verify(ctx, rawIDToken)
	if err != nil {
		return "", "", nil, fmt.Errorf("oidc: verify id token: %w", err)
	}
	if idToken.Subject == "" {
		return "", "", nil, fmt.Errorf("oidc: id token missing sub claim")
	}

	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return "", "", nil, fmt.Errorf("oidc: decode id token claims: %w", err)
	}

	if s.cfg.RequireNonce || params.ExpectedNonce != "" {
		if !constantTimeEqual(idToken.Nonce, params.ExpectedNonce) {
			return "", "", nil, fmt.Errorf("oidc: id token nonce mismatch: %w", domain.ErrUnauthenticated)
		}
	}

	if len(idToken.Audience) > 1 {
		azp, _ := claims["azp"].(string)
		if azp == "" {
			return "", "", nil, fmt.Errorf("oidc: multi-audience id token missing azp claim: %w", domain.ErrUnauthenticated)
		}
		if azp != s.cfg.ClientID {
			return "", "", nil, fmt.Errorf("oidc: id token azp %q does not match client_id: %w", azp, domain.ErrUnauthenticated)
		}
	}

	if claimMissing(claims, s.usernameClaim) || claimMissing(claims, "email") || claimMissing(claims, s.groupsClaim) {
		s.mergeUserInfo(ctx, p, tok, claims)
	}

	// Enforce email_verified AFTER the userinfo merge so a false value supplied
	// only by userinfo (when the ID token omits the claim) is not bypassed.
	if s.cfg.RequireEmailVerified {
		if v, ok := claims["email_verified"].(bool); ok && !v {
			return "", "", nil, fmt.Errorf("oidc: email not verified: %w", domain.ErrForbidden)
		}
	}

	username, err := s.resolveUsername(claims)
	if err != nil {
		return "", "", nil, err
	}
	groups := s.resolveGroups(claims)

	if allowlist := s.effectiveAllowedGroups(); len(allowlist) > 0 && !orgsIntersect(allowlist, groups) {
		return "", "", nil, domain.ErrForbidden
	}

	mappedGroups := mapGroups(s.mapper, groups)
	cred := &Credential{Provider: s.cfg.ProviderID, AccessToken: tok.AccessToken, RefreshToken: tok.RefreshToken, ExpiresAt: tok.Expiry}
	access, refresh, u, err = completeOAuthLogin(ctx, s.lc, s.cfg.ProviderID, idToken.Subject, s.issuerURL, username, groups, mappedGroups, cred)
	if err != nil {
		return "", "", nil, fmt.Errorf("oidc oauth: %w", err)
	}
	return access, refresh, u, nil
}

func (s *OIDCOAuthService) effectiveAllowedGroups() []string {
	out := make([]string, 0, len(s.cfg.AllowedGroups)+len(s.cfg.AllowedOrgs))
	seen := make(map[string]struct{}, len(s.cfg.AllowedGroups)+len(s.cfg.AllowedOrgs))
	for _, list := range [][]string{s.cfg.AllowedGroups, s.cfg.AllowedOrgs} {
		for _, g := range list {
			if _, dup := seen[g]; dup {
				continue
			}
			seen[g] = struct{}{}
			out = append(out, g)
		}
	}
	return out
}

func (s *OIDCOAuthService) mergeUserInfo(ctx context.Context, p *oidc.Provider, tok *oauth2.Token, claims map[string]any) {
	ui, err := p.UserInfo(ctx, oauth2.StaticTokenSource(tok))
	if err != nil {
		s.logger.Warn("oidc: userinfo fetch failed, using id token claims only", nil)
		return
	}
	var userInfoClaims map[string]any
	if err := ui.Claims(&userInfoClaims); err != nil {
		s.logger.Warn("oidc: userinfo claims decode failed, using id token claims only", nil)
		return
	}
	for k, v := range userInfoClaims {
		if _, ok := claims[k]; !ok {
			claims[k] = v
		}
	}
}

func (s *OIDCOAuthService) resolveUsername(claims map[string]any) (string, error) {
	if name := claimString(claims, s.usernameClaim); name != "" {
		return name, nil
	}
	if email := claimString(claims, "email"); email != "" {
		return email, nil
	}
	return "", fmt.Errorf("oidc: no usable username claim (tried %q and %q)", s.usernameClaim, "email")
}

func (s *OIDCOAuthService) resolveGroups(claims map[string]any) []string {
	raw, ok := claims[s.groupsClaim]
	if !ok {
		return nil
	}
	switch v := raw.(type) {
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			out = append(out, fmt.Sprintf("%v", e))
		}
		return out
	default:
		return nil
	}
}

// Revalidate re-checks the user's current IdP group membership using the stored
// credential. It returns ErrOAuthCredentialExpired when the credential can no
// longer be used (non-destructive), ErrOAuthNotLeaderRefresh on a follower, and
// ErrForbidden when membership no longer satisfies the allowlist.
func (s *OIDCOAuthService) Revalidate(ctx context.Context, u *domain.User) ([]string, error) {
	if u.OAuthTokenCiphertext == "" {
		return nil, domain.ErrOAuthNoCredential
	}
	cred, err := OpenCredential(s.sealer, u.OAuthTokenCiphertext)
	if err != nil || cred == nil {
		return nil, domain.ErrOAuthCredentialExpired
	}
	if !s.leader() {
		return nil, domain.ErrOAuthNotLeaderRefresh
	}
	if s.httpClient != nil {
		ctx = oidc.ClientContext(ctx, s.httpClient)
	}
	p, err := s.discover(ctx)
	if err != nil {
		return nil, fmt.Errorf("oidc: discover provider: %w", err)
	}

	ts := &refreshingSource{s: s, ctx: ctx, p: p, u: u, cred: cred}
	ui, err := p.UserInfo(ctx, ts)
	if err != nil {
		if !oauthTokenRevoked(err) {
			return nil, fmt.Errorf("oidc: userinfo: %w", err)
		}
		s.logger.Debug("oidc: userinfo returned 401, attempting token refresh", map[string]any{"user_id": u.ID})
		if _, refreshErr := ts.Token(); refreshErr != nil {
			if errors.Is(refreshErr, domain.ErrOAuthNotLeaderRefresh) {
				return nil, domain.ErrOAuthNotLeaderRefresh
			}
			if oauthTokenRevoked(refreshErr) {
				return nil, domain.ErrOAuthCredentialExpired
			}
			return nil, fmt.Errorf("oidc: userinfo: %w", err)
		}
		ui, err = p.UserInfo(ctx, ts)
		if err != nil {
			if oauthTokenRevoked(err) {
				return nil, domain.ErrOAuthCredentialExpired
			}
			return nil, fmt.Errorf("oidc: userinfo: %w", err)
		}
	}
	var claims map[string]any
	if err := ui.Claims(&claims); err != nil {
		return nil, fmt.Errorf("oidc: userinfo decode: %w", err)
	}
	groups := s.resolveGroups(claims)
	if allowlist := s.effectiveAllowedGroups(); len(allowlist) > 0 && !orgsIntersect(allowlist, groups) {
		return nil, domain.ErrForbidden
	}
	return groups, nil
}

// refreshingSource wraps an oauth2.TokenSource that refreshes the upstream
// credential and persists it back to the user record on success.
type refreshingSource struct {
	s    *OIDCOAuthService
	ctx  context.Context
	p    *oidc.Provider
	u    *domain.User
	cred *Credential
}

func (rs *refreshingSource) Token() (*oauth2.Token, error) {
	baseSrc := rs.s.oauth2Config(rs.p.Endpoint()).TokenSource(rs.ctx, &oauth2.Token{
		AccessToken:  rs.cred.AccessToken,
		RefreshToken: rs.cred.RefreshToken,
		Expiry:       rs.cred.ExpiresAt,
	})
	tok, err := baseSrc.Token()
	if err != nil {
		return nil, err
	}
	if tok.AccessToken != rs.cred.AccessToken || tok.RefreshToken != rs.cred.RefreshToken {
		rs.cred.AccessToken = tok.AccessToken
		rs.cred.RefreshToken = tok.RefreshToken
		rs.cred.ExpiresAt = tok.Expiry
		ct, err := SealCredential(rs.s.sealer, rs.cred)
		if err != nil {
			rs.s.logger.Warn("oauth: re-encrypt refreshed credential failed", map[string]any{"user_id": rs.u.ID})
		} else if ct != "" {
			rs.u.OAuthTokenCiphertext = ct
			persistCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := rs.s.lc.userStore.Update(persistCtx, rs.u); err != nil {
				if errors.Is(err, domain.ErrNotLeader) {
					return nil, domain.ErrOAuthNotLeaderRefresh
				}
				rs.s.logger.Warn("oauth: persist refreshed credential failed", map[string]any{"user_id": rs.u.ID})
			}
		}
	}
	return tok, nil
}

// oauthTokenRevoked reports whether err signals an unusable OIDC credential.
func oauthTokenRevoked(err error) bool {
	var rerr *oauth2.RetrieveError
	if errors.As(err, &rerr) {
		if rerr.ErrorCode == "invalid_grant" || rerr.ErrorCode == "invalid_token" {
			return true
		}
		return rerr.Response != nil && rerr.Response.StatusCode == http.StatusUnauthorized
	}
	msg := err.Error()
	return strings.Contains(msg, "invalid_grant") ||
		strings.Contains(msg, "invalid_token") ||
		strings.Contains(msg, "401 Unauthorized")
}

// NewOAuthHTTPClient creates an HTTP client that trusts the CA certificate at
// caCertPath in addition to the system pool, refuses cross-origin redirects,
// and caps response bodies at MaxResponseBodyBytes. When caCertPath is empty
// the system certificate pool is used.
func NewOAuthHTTPClient(caCertPath string, timeout time.Duration) (*http.Client, error) {
	if timeout <= 0 {
		timeout = DefaultHTTPTimeout
	}
	transport := &http.Transport{
		ResponseHeaderTimeout: timeout,
		DialContext:           (&net.Dialer{Timeout: timeout}).DialContext,
	}
	if caCertPath != "" {
		caCert, err := os.ReadFile(caCertPath) // #nosec G304
		if err != nil {
			return nil, fmt.Errorf("read OAuth CA cert %s: %w", caCertPath, err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("OAuth CA cert %s: no valid PEM certificates found", caCertPath)
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return &http.Client{
		Timeout:       timeout,
		Transport:     &cappedTransport{base: transport},
		CheckRedirect: refuseCrossOriginRedirect,
	}, nil
}

func refuseCrossOriginRedirect(req *http.Request, via []*http.Request) error {
	if len(via) > 0 && (req.URL.Scheme != via[0].URL.Scheme || req.URL.Host != via[0].URL.Host) {
		return fmt.Errorf("cross-origin redirect refused: %s", req.URL.Host)
	}
	return nil
}

// cappedTransport wraps response bodies with a MaxResponseBodyBytes limit
// (CWE-400).
type cappedTransport struct {
	base http.RoundTripper
}

func (t *cappedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	resp.Body = &limitReadCloser{rc: resp.Body, limit: MaxResponseBodyBytes}
	return resp, nil
}

type limitReadCloser struct {
	rc    io.ReadCloser
	limit int64
	read  int64
}

func (l *limitReadCloser) Read(p []byte) (int, error) {
	if l.read >= l.limit {
		var one [1]byte
		n, err := l.rc.Read(one[:])
		if n > 0 {
			return 0, fmt.Errorf("response body exceeds %d bytes", l.limit)
		}
		return 0, err
	}
	if int64(len(p)) > l.limit-l.read {
		p = p[:l.limit-l.read]
	}
	n, err := l.rc.Read(p)
	l.read += int64(n)
	return n, err
}

func (l *limitReadCloser) Close() error { return l.rc.Close() }

func claimString(claims map[string]any, key string) string {
	v, ok := claims[key]
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

func claimMissing(claims map[string]any, key string) bool {
	_, ok := claims[key]
	return !ok
}
