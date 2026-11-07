package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/disaster37/go-auth/crypto"
	"github.com/disaster37/go-auth/domain"
	"github.com/disaster37/go-auth/jwt"
	"github.com/disaster37/go-auth/observ"
	"github.com/disaster37/go-auth/password"
	"github.com/disaster37/go-auth/store"
)

// GitHubConfig configures a GitHubOAuthService.
type GitHubConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	AllowedOrgs  []string
	AllowedTeams []string
	AdminGroups  []string
	DefaultGroup string
	TokenURL     string
	APIBaseURL   string
	EnablePKCE   bool
}

// GitHubOAuthService implements the GitHub OAuth login flow (server-side code
// exchange).
type GitHubOAuthService struct {
	cfg    GitHubConfig
	mapper *GroupMapper
	lc     loginContext
	http   *http.Client
	logger observ.Logger
}

// NewGitHubOAuthService returns a GitHubOAuthService.
func NewGitHubOAuthService(
	cfg GitHubConfig,
	mapper *GroupMapper,
	users *password.Service,
	userStore store.UserStore,
	groups store.GroupStore,
	jwtSvc *jwt.Service,
	sealer crypto.Sealer,
	httpClient *http.Client,
	logger observ.Logger,
) *GitHubOAuthService {
	if logger == nil {
		logger = observ.NewNoopLogger()
	}
	if cfg.TokenURL == "" {
		cfg.TokenURL = "https://github.com/login/oauth/access_token"
	}
	if cfg.APIBaseURL == "" {
		cfg.APIBaseURL = "https://api.github.com"
	}
	if httpClient == nil {
		httpClient, _ = NewOAuthHTTPClient("", DefaultHTTPTimeout)
	}
	return &GitHubOAuthService{
		cfg:    cfg,
		mapper: mapper,
		lc: loginContext{
			users:        users,
			userStore:    userStore,
			groups:       groups,
			jwt:          jwtSvc,
			sealer:       sealer,
			logger:       logger,
			adminGroups:  cfg.AdminGroups,
			defaultGroup: cfg.DefaultGroup,
			autoCreate:   true,
		},
		http:   httpClient,
		logger: logger,
	}
}

// Name returns the provider ID.
func (s *GitHubOAuthService) Name() string { return "github" }

// LoginURL returns the GitHub authorize URL with the given state token.
func (s *GitHubOAuthService) LoginURL(params AuthorizeParams) string {
	v := url.Values{}
	v.Set("client_id", s.cfg.ClientID)
	v.Set("redirect_uri", s.cfg.RedirectURL)
	v.Set("scope", "read:org")
	v.Set("state", params.State)
	if s.cfg.EnablePKCE && params.CodeChallenge != "" {
		v.Set("code_challenge", params.CodeChallenge)
		v.Set("code_challenge_method", "S256")
	}
	return fmt.Sprintf("https://github.com/login/oauth/authorize?%s", v.Encode())
}

// Complete exchanges the code for a GitHub access token, fetches the user
// profile, orgs and (when needed) teams, enforces the allowlist, resolves the
// local user, and issues a JWT pair.
func (s *GitHubOAuthService) Complete(ctx context.Context, params CompleteParams) (access, refresh string, u *domain.User, err error) {
	accessToken, err := s.exchangeCode(ctx, params.Code, params.CodeVerifier)
	if err != nil {
		return "", "", nil, fmt.Errorf("exchange code: %w", err)
	}
	ghUser, err := s.fetchUser(ctx, accessToken)
	if err != nil {
		return "", "", nil, fmt.Errorf("fetch github user: %w", err)
	}
	orgs, teams, err := s.fetchMembership(ctx, accessToken)
	if err != nil {
		return "", "", nil, err
	}
	if err := s.enforceAllowlist(orgs, teams); err != nil {
		return "", "", nil, err
	}

	providerGroups := make([]string, 0, len(orgs)+len(teams))
	providerGroups = append(providerGroups, orgs...)
	providerGroups = append(providerGroups, teams...)
	mappedGroups := mapGroups(s.mapper, providerGroups)

	cred := &Credential{Provider: "github", AccessToken: accessToken}
	access, refresh, u, err = completeOAuthLogin(ctx, s.lc, "github", strconv.Itoa(ghUser.ID), "", ghUser.Login, providerGroups, mappedGroups, cred)
	if err != nil {
		return "", "", nil, fmt.Errorf("github oauth: %w", err)
	}
	return access, refresh, u, nil
}

func (s *GitHubOAuthService) exchangeCode(ctx context.Context, code, codeVerifier string) (string, error) {
	form := url.Values{
		"client_id":     {s.cfg.ClientID},
		"client_secret": {s.cfg.ClientSecret},
		"code":          {code},
		"redirect_uri":  {s.cfg.RedirectURL},
	}
	if s.cfg.EnablePKCE && codeVerifier != "" {
		form.Set("code_verifier", codeVerifier)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.http.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	var out struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := decodeCapped(resp.Body, &out); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}
	if out.Error != "" {
		return "", fmt.Errorf("github token error: %s", out.Error)
	}
	if out.AccessToken == "" {
		return "", fmt.Errorf("empty access token")
	}
	return out.AccessToken, nil
}

type githubUser struct {
	ID    int    `json:"id"`
	Login string `json:"login"`
}

func (s *GitHubOAuthService) fetchUser(ctx context.Context, accessToken string) (*githubUser, error) {
	var u githubUser
	if err := s.getJSON(ctx, "/user", accessToken, &u); err != nil {
		return nil, err
	}
	if u.ID == 0 || u.Login == "" {
		return nil, fmt.Errorf("incomplete github user")
	}
	return &u, nil
}

func (s *GitHubOAuthService) fetchOrgs(ctx context.Context, accessToken string) ([]string, error) {
	var out []struct {
		Login string `json:"login"`
	}
	if err := s.getJSON(ctx, "/user/orgs", accessToken, &out); err != nil {
		return nil, err
	}
	orgs := make([]string, 0, len(out))
	for _, o := range out {
		orgs = append(orgs, o.Login)
	}
	return orgs, nil
}

func (s *GitHubOAuthService) fetchTeams(ctx context.Context, accessToken string) ([]string, error) {
	var out []struct {
		Slug string `json:"slug"`
		Org  struct {
			Login string `json:"login"`
		} `json:"organization"`
	}
	if err := s.getJSON(ctx, "/user/teams", accessToken, &out); err != nil {
		return nil, err
	}
	teams := make([]string, 0, len(out))
	for _, t := range out {
		if t.Slug == "" || t.Org.Login == "" {
			continue
		}
		teams = append(teams, fmt.Sprintf("%s/%s", t.Org.Login, t.Slug))
	}
	return teams, nil
}

// fetchMembership fetches orgs and (when needed) teams.
func (s *GitHubOAuthService) fetchMembership(ctx context.Context, accessToken string) (orgs, teams []string, err error) {
	orgs, err = s.fetchOrgs(ctx, accessToken)
	if err != nil {
		return nil, nil, fmt.Errorf("fetch github orgs: %w", err)
	}
	if len(s.cfg.AllowedTeams) > 0 || len(s.cfg.AdminGroups) > 0 || s.mapper.Active() {
		teams, err = s.fetchTeams(ctx, accessToken)
		if err != nil {
			if len(s.cfg.AllowedTeams) > 0 {
				return nil, nil, fmt.Errorf("fetch github teams: %w", err)
			}
			s.logger.Warn("oauth: github teams fetch failed; mapping will use orgs only", nil)
			teams = nil
		}
	}
	return orgs, teams, nil
}

func (s *GitHubOAuthService) enforceAllowlist(orgs, teams []string) error {
	if len(s.cfg.AllowedOrgs) > 0 && !orgsIntersect(s.cfg.AllowedOrgs, orgs) {
		return domain.ErrForbidden
	}
	if len(s.cfg.AllowedTeams) > 0 && !orgsIntersect(s.cfg.AllowedTeams, teams) {
		return domain.ErrForbidden
	}
	return nil
}

func (s *GitHubOAuthService) getJSON(ctx context.Context, path, accessToken string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s%s", s.cfg.APIBaseURL, path), http.NoBody)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "go-auth")

	resp, err := s.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return &githubStatusError{Path: path, StatusCode: resp.StatusCode}
	}
	return decodeCapped(resp.Body, out)
}

// githubStatusError reports a non-200 GitHub API response.
type githubStatusError struct {
	Path       string
	StatusCode int
}

func (e *githubStatusError) Error() string {
	return fmt.Sprintf("github api %s status %d", e.Path, e.StatusCode)
}

// Revalidate re-checks the user's current GitHub membership using the stored
// credential. It returns ErrSessionRevoked when the token is gone (401/404) and
// ErrForbidden when membership no longer satisfies the allowlist.
func (s *GitHubOAuthService) Revalidate(ctx context.Context, u *domain.User) ([]string, error) {
	if u.OAuthTokenCiphertext == "" {
		return nil, domain.ErrOAuthNoCredential
	}
	cred, err := OpenCredential(s.lc.sealer, u.OAuthTokenCiphertext)
	if err != nil || cred == nil {
		return nil, domain.ErrSessionRevoked
	}
	if _, err := s.fetchUser(ctx, cred.AccessToken); err != nil {
		var statusErr *githubStatusError
		if errors.As(err, &statusErr) && (statusErr.StatusCode == http.StatusUnauthorized || statusErr.StatusCode == http.StatusNotFound) {
			return nil, domain.ErrSessionRevoked
		}
		return nil, err
	}
	orgs, teams, err := s.fetchMembership(ctx, cred.AccessToken)
	if err != nil {
		return nil, err
	}
	if err := s.enforceAllowlist(orgs, teams); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(orgs)+len(teams))
	out = append(out, orgs...)
	out = append(out, teams...)
	return out, nil
}

// decodeCapped decodes JSON from r, capping the body at MaxResponseBodyBytes.
func decodeCapped(r io.Reader, out any) error {
	data, err := io.ReadAll(io.LimitReader(r, MaxResponseBodyBytes+1))
	if err != nil {
		return err
	}
	if len(data) > MaxResponseBodyBytes {
		return fmt.Errorf("response body exceeds %d bytes", MaxResponseBodyBytes)
	}
	return json.Unmarshal(data, out)
}

var _ Provider = (*GitHubOAuthService)(nil)
var _ Provider = (*OIDCOAuthService)(nil)
