# CloudWeGo Hertz integration

The core packages do not import Hertz. A Hertz application adapts the
framework-agnostic primitives in roughly twenty lines.

```go
package hertzadapter

import (
	"context"
	"net"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/disaster37/go-secguard/realip"

	goauth "github.com/disaster37/go-auth"
	"github.com/disaster37/go-auth/httpcookie"
	"github.com/disaster37/go-auth/nethttp"
)

// RequireAuth resolves the bearer credential and stores the identity in the
// Hertz request context.
func RequireAuth(svc *goauth.Service, cfg httpcookie.Config) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		bearer := string(c.GetHeader("Authorization"))
		if len(bearer) > 7 && bearer[:7] == "Bearer " {
			bearer = bearer[7:]
		} else if v := c.Cookie(cfg.AccessName); len(v) > 0 {
			bearer = string(v)
		}
		id, err := svc.Resolve(ctx, bearer)
		if err != nil {
			writeError(c, err)
			c.Abort()
			return
		}
		c.Set("identity", id)
		c.Next(ctx)
	}
}

// SetPair writes the access/refresh cookies using the framework-agnostic specs.
func SetPair(c *app.RequestContext, cfg httpcookie.Config, isTLS bool, access, refresh string, accessTTL, refreshTTL int) {
	a, r := httpcookie.IssuePairSpecs(cfg, isTLS, access, refresh, accessTTL, refreshTTL)
	c.SetCookie(a.Name, a.Value, a.MaxAge, a.Path, a.Domain, a.SameSite)
	c.SetCookie(r.Name, r.Value, r.MaxAge, r.Path, r.Domain, r.SameSite)
}

// RealIP resolves the client IP behind trusted proxies.
func RealIP(c *app.RequestContext, behindProxy bool, trusted []*net.IPNet) string {
	ip, err := realip.ExtractRealIP(
		string(c.RemoteAddr().String()),
		string(c.GetHeader("X-Forwarded-For")),
		string(c.GetHeader("X-Real-IP")),
		behindProxy,
		trusted,
	)
	if err != nil {
		return ""
	}
	return ip.String()
}

func writeError(c *app.RequestContext, err error) {
	status, message := statusFor(err)
	c.JSON(status, map[string]string{"error": message})
}

func statusFor(err error) (int, string) {
	// Reuse the same mapping as nethttp.StatusCodeForError.
	return nethttp.StatusCodeForError(err)
}
```

Notes:

- `httpcookie.Spec` is framework-agnostic; `Spec.ToStdlib()` is available when
  you need a `*http.Cookie`.
- Use `headers.DefaultSecurityHeaders` and `headers.CheckMutationOrigin` from
  `github.com/disaster37/go-secguard/headers` in Hertz middleware exactly as the
  `nethttp` adapter does. `headers.CheckMutationOrigin` returns
  `sgdomain.ErrOriginNotAllowed` (from `github.com/disaster37/go-secguard/domain`);
  `nethttp.StatusCodeForError` maps that sentinel to HTTP 403.
- The `nethttp` package is optional; importing it from a Hertz binary is fine
  when you want the shared error mapping, but the core packages remain
  framework-free.
