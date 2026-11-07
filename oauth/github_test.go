package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/disaster37/go-auth/domain"
	"github.com/disaster37/go-auth/jwt"
	"github.com/disaster37/go-auth/observ"
	"github.com/disaster37/go-auth/password"
	"github.com/disaster37/go-auth/store"
)

type githubMock struct {
	server      *httptest.Server
	userStatus  int
	teamsStatus int
	orgs        []string
	teams       []string
	tokenError  string
	accessToken string
}

func newGitHubMock(t *testing.T) *githubMock {
	t.Helper()
	m := &githubMock{accessToken: "gh-token", orgs: []string{"acme"}, teams: []string{"acme/devs"}}
	mux := http.NewServeMux()
	mux.HandleFunc("/login/oauth/access_token", func(w http.ResponseWriter, _ *http.Request) {
		if m.tokenError != "" {
			writeTestJSON(w, map[string]any{"error": m.tokenError})
			return
		}
		writeTestJSON(w, map[string]any{"access_token": m.accessToken})
	})
	mux.HandleFunc("/user", func(w http.ResponseWriter, _ *http.Request) {
		if m.userStatus != 0 {
			w.WriteHeader(m.userStatus)
			return
		}
		writeTestJSON(w, map[string]any{"id": 42, "login": "alice"})
	})
	mux.HandleFunc("/user/orgs", func(w http.ResponseWriter, _ *http.Request) {
		out := make([]map[string]string, 0, len(m.orgs))
		for _, o := range m.orgs {
			out = append(out, map[string]string{"login": o})
		}
		writeTestJSON(w, out)
	})
	mux.HandleFunc("/user/teams", func(w http.ResponseWriter, _ *http.Request) {
		if m.teamsStatus != 0 {
			w.WriteHeader(m.teamsStatus)
			return
		}
		out := make([]map[string]any, 0, len(m.teams))
		for _, tm := range m.teams {
			parts := strings.SplitN(tm, "/", 2)
			out = append(out, map[string]any{"slug": parts[1], "organization": map[string]string{"login": parts[0]}})
		}
		writeTestJSON(w, out)
	})
	m.server = httptest.NewServer(mux)
	t.Cleanup(m.server.Close)
	return m
}

func writeTestJSON(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}

func newGitHubService(t *testing.T, m *githubMock, cfg GitHubConfig) (*GitHubOAuthService, *store.MemoryUserStore, *store.MemoryGroupStore) {
	t.Helper()
	users := store.NewMemoryUserStore()
	groups := store.NewMemoryGroupStore()
	_ = groups.Create(context.Background(), &domain.Group{ID: "g-default", Name: "default"})
	jwtSvc, _ := jwt.NewService(jwt.Config{Secret: []byte("0123456789abcdef0123456789abcdef")})
	cfg.ClientID = "client"
	cfg.ClientSecret = "secret"
	cfg.RedirectURL = "http://localhost/callback"
	cfg.TokenURL = m.server.URL + "/login/oauth/access_token"
	cfg.APIBaseURL = m.server.URL
	svc := NewGitHubOAuthService(cfg, nil, password.NewService(users), users, groups, jwtSvc, testSealer(t), nil, observ.NewNoopLogger())
	return svc, users, groups
}

func TestGitHubLoginURL(t *testing.T) {
	m := newGitHubMock(t)
	svc, _, _ := newGitHubService(t, m, GitHubConfig{})
	url := svc.LoginURL(AuthorizeParams{State: "state-1", CodeChallenge: "challenge-1"})
	if !strings.Contains(url, "state-1") || !strings.Contains(url, "client_id=client") {
		t.Fatalf("login url: %s", url)
	}
	if svc.Name() != "github" {
		t.Fatalf("name=%q", svc.Name())
	}
}

func TestGitHubComplete(t *testing.T) {
	m := newGitHubMock(t)
	svc, users, _ := newGitHubService(t, m, GitHubConfig{AllowedOrgs: []string{"acme"}, AdminGroups: []string{"acme/devs"}})
	access, refresh, u, err := svc.Complete(context.Background(), CompleteParams{Code: "code"})
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if access == "" || refresh == "" || u == nil {
		t.Fatal("expected token pair")
	}
	if u.Role != domain.RoleAdmin {
		t.Fatalf("expected admin via team, got %s", u.Role)
	}
	stored, _ := users.Get(context.Background(), u.ID)
	if stored.OAuthTokenCiphertext == "" {
		t.Fatal("expected sealed credential")
	}
}

func TestGitHubCompleteForbidden(t *testing.T) {
	m := newGitHubMock(t)
	svc, _, _ := newGitHubService(t, m, GitHubConfig{AllowedOrgs: []string{"other"}})
	if _, _, _, err := svc.Complete(context.Background(), CompleteParams{Code: "code"}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("forbidden: %v", err)
	}
}

func TestGitHubCompleteTokenError(t *testing.T) {
	m := newGitHubMock(t)
	m.tokenError = "bad_verification_code"
	svc, _, _ := newGitHubService(t, m, GitHubConfig{})
	if _, _, _, err := svc.Complete(context.Background(), CompleteParams{Code: "code"}); err == nil {
		t.Fatal("token error must fail")
	}
}

func TestGitHubRevalidate(t *testing.T) {
	ctx := context.Background()
	m := newGitHubMock(t)
	svc, users, _ := newGitHubService(t, m, GitHubConfig{AllowedOrgs: []string{"acme"}})
	cred, _ := SealCredential(svc.lc.sealer, &Credential{Provider: "github", AccessToken: "gh-token"})
	u := &domain.User{ID: "u1", OAuthProvider: "github", OAuthTokenCiphertext: cred}
	_ = users.Create(ctx, u)

	groups, err := svc.Revalidate(ctx, u)
	if err != nil || len(groups) == 0 {
		t.Fatalf("revalidate: %v %v", groups, err)
	}

	// Revoked token -> session revoked.
	m.userStatus = http.StatusUnauthorized
	if _, err := svc.Revalidate(ctx, u); !errors.Is(err, domain.ErrSessionRevoked) {
		t.Fatalf("revoked: %v", err)
	}
}

func TestGitHubRevalidateNoCredential(t *testing.T) {
	m := newGitHubMock(t)
	svc, _, _ := newGitHubService(t, m, GitHubConfig{})
	if _, err := svc.Revalidate(context.Background(), &domain.User{ID: "u1"}); !errors.Is(err, domain.ErrOAuthNoCredential) {
		t.Fatalf("no credential: %v", err)
	}
}

func TestGitHubRevalidateForbidden(t *testing.T) {
	ctx := context.Background()
	m := newGitHubMock(t)
	svc, users, _ := newGitHubService(t, m, GitHubConfig{AllowedOrgs: []string{"other"}})
	cred, _ := SealCredential(svc.lc.sealer, &Credential{Provider: "github", AccessToken: "gh-token"})
	u := &domain.User{ID: "u1", OAuthTokenCiphertext: cred}
	_ = users.Create(ctx, u)
	if _, err := svc.Revalidate(ctx, u); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("forbidden: %v", err)
	}
}
