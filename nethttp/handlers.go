package nethttp

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"

	goauth "github.com/disaster37/go-auth"
	"github.com/disaster37/go-auth/domain"
	"github.com/disaster37/go-auth/httpcookie"
	"github.com/disaster37/go-auth/jwt"
	"github.com/disaster37/go-auth/oauth"
)

// maxLoginBodyBytes caps the login request body (CWE-400).
const maxLoginBodyBytes = 64 << 10

// LoginHandler authenticates a username/password and issues the JWT cookie
// pair.
func LoginHandler(svc *goauth.Service, jwtSvc *jwt.Service, cookieCfg httpcookie.Config, isTLS bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodyBytes)
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			WriteError(w, domain.ErrValidation)
			return
		}
		access, refresh, u, err := svc.Login(r.Context(), body.Username, body.Password)
		if err != nil {
			WriteError(w, err)
			return
		}
		setPairCookies(w, cookieCfg, isTLS, jwtSvc, access, refresh)
		writeJSON(w, map[string]any{"ok": true, "user_id": u.ID, "username": u.Username})
	}
}

// RefreshHandler rotates the JWT cookie pair from the refresh cookie.
func RefreshHandler(svc *goauth.Service, jwtSvc *jwt.Service, cookieCfg httpcookie.Config, isTLS bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(cookieCfg.RefreshName)
		if err != nil || c.Value == "" {
			WriteError(w, domain.ErrUnauthenticated)
			return
		}
		access, refresh, err := svc.Refresh(r.Context(), c.Value)
		if err != nil {
			WriteError(w, err)
			return
		}
		setPairCookies(w, cookieCfg, isTLS, jwtSvc, access, refresh)
		writeJSON(w, map[string]any{"ok": true})
	}
}

// LogoutHandler revokes the caller's JWTs and clears the cookie pair.
func LogoutHandler(svc *goauth.Service, cookieCfg httpcookie.Config, isTLS bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bearer := ExtractBearer(r, cookieCfg.AccessName, false)
		if bearer != "" {
			if err := svc.Logout(r.Context(), bearer); err != nil {
				WriteError(w, err)
				return
			}
		}
		accessSpec, refreshSpec := httpcookie.ClearPairSpecs(cookieCfg, isTLS)
		http.SetCookie(w, accessSpec.ToStdlib())
		http.SetCookie(w, refreshSpec.ToStdlib())
		writeJSON(w, map[string]any{"ok": true})
	}
}

// OAuthLoginHandler initiates the OAuth2/OIDC login flow.
func OAuthLoginHandler(provider oauth.Provider, jwtSvc *jwt.Service, cookieCfg httpcookie.Config, isTLS bool, defaultPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		redirect := httpcookie.SafeRedirectPath(r.URL.Query().Get("redirect"), defaultPath)
		nonce, err := oauth.GenerateNonce()
		if err != nil {
			WriteError(w, err)
			return
		}
		verifier, err := oauth.GeneratePKCEVerifier()
		if err != nil {
			WriteError(w, err)
			return
		}
		state, err := jwtSvc.IssueOAuthState(redirect, nonce, verifier, provider.Name())
		if err != nil {
			WriteError(w, err)
			return
		}
		stateSpec := httpcookie.IssueOAuthStateSpec(cookieCfg, isTLS, nonce, httpcookie.DefaultStateMaxAge)
		http.SetCookie(w, stateSpec.ToStdlib())
		http.Redirect(w, r, provider.LoginURL(oauth.AuthorizeParams{
			State:         state,
			Nonce:         nonce,
			CodeChallenge: oauth.ComputePKCEChallenge(verifier),
		}), http.StatusFound)
	}
}

// OAuthCallbackHandler completes the OAuth2/OIDC login flow, validating the
// state JWT and its constant-time cookie nonce binding.
func OAuthCallbackHandler(provider oauth.Provider, jwtSvc *jwt.Service, cookieCfg httpcookie.Config, isTLS bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")
		if code == "" || state == "" {
			WriteError(w, domain.ErrValidation)
			return
		}
		cookie, err := r.Cookie(cookieCfg.StateName)
		if err != nil {
			WriteError(w, domain.ErrUnauthenticated)
			return
		}
		claims, err := jwtSvc.ParseOAuthState(state)
		if err != nil {
			WriteError(w, domain.ErrUnauthenticated)
			return
		}
		if subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(cookie.Value)) != 1 {
			WriteError(w, domain.ErrUnauthenticated)
			return
		}
		clearSpec := httpcookie.ClearOAuthStateSpec(cookieCfg, isTLS)
		http.SetCookie(w, clearSpec.ToStdlib())

		access, refresh, _, err := provider.Complete(r.Context(), oauth.CompleteParams{
			Code:          code,
			ExpectedNonce: claims.Nonce,
			CodeVerifier:  claims.CodeVerifier,
		})
		if err != nil {
			WriteError(w, err)
			return
		}
		setPairCookies(w, cookieCfg, isTLS, jwtSvc, access, refresh)
		http.Redirect(w, r, httpcookie.SafeRedirectPath(claims.Username, "/"), http.StatusFound) // #nosec G710
	}
}

func setPairCookies(w http.ResponseWriter, cookieCfg httpcookie.Config, isTLS bool, jwtSvc *jwt.Service, access, refresh string) {
	accessSpec, refreshSpec := httpcookie.IssuePairSpecs(
		cookieCfg, isTLS, access, refresh,
		int(jwtSvc.AccessTTL().Seconds()), int(jwtSvc.RefreshTTL().Seconds()),
	)
	http.SetCookie(w, accessSpec.ToStdlib())
	http.SetCookie(w, refreshSpec.ToStdlib())
}

func writeJSON(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(body)
}
