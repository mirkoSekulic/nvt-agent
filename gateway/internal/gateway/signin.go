package gateway

import (
	"bytes"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// The gateway never starts an OAuth/OIDC flow on its own. An unauthenticated
// browser navigation renders this page instead, so authorization only begins
// after the user activates the sign-in control. Automatic redirection is a poor
// experience once an identity-provider SSO session exists: the flow completes
// silently and the user cannot tell that signing out did anything.
//
// One renderer serves both the unauthenticated and the signed-out state, and it
// stays provider-generic: no provider name, endpoint, or configuration appears
// here or in the rendered page.
type signInPageData struct {
	Title         string
	Heading       string
	Message       string
	SignInURL     string
	BrandMarkPath string
	TouchIconPath string
	FaviconPath   string
}

var signInTemplate = template.Must(template.New("signin").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="theme-color" content="#C89532">
  <title>{{ .Title }}</title>
  <link rel="icon" href="{{ .FaviconPath }}" sizes="any">
  <link rel="apple-touch-icon" href="{{ .TouchIconPath }}" sizes="192x192">
  <style>
    * { box-sizing: border-box; }
    body { min-height: 100vh; display: grid; place-items: center; margin: 0; padding: 1rem; font-family: system-ui, sans-serif; color: #17202a; background: #fbfaf7; }
    main { width: min(100%, 25rem); padding: 2rem; text-align: center; background: #fff; border: 1px solid #e2ddd2; border-radius: .8rem; box-shadow: 0 .75rem 2.5rem rgb(23 32 42 / 8%); }
    img { display: block; width: 4rem; height: 4rem; margin: 0 auto .75rem; }
    .brand { margin: 0; font-size: 1.15rem; font-weight: 750; }
    h1 { margin: 1.5rem 0 .5rem; font-size: 1.5rem; }
    p { color: #596879; line-height: 1.5; }
    a.signin { display: inline-block; margin-top: .4rem; padding: .55rem .9rem; border-radius: .4rem; color: #fff; background: #17202a; text-decoration: none; font-weight: 600; }
    a.signin:focus-visible { outline: 3px solid #D6A13A; outline-offset: 3px; }
  </style>
</head>
<body>
  <main>
    <img src="{{ .BrandMarkPath }}" alt="">
    <p class="brand">NVT Agent</p>
    <h1>{{ .Heading }}</h1>
    <p>{{ .Message }}</p>
    <a class="signin" href="{{ .SignInURL }}">Sign in</a>
  </main>
</body>
</html>
`))

// renderSignInPage writes the sign-in page for a browser read. It resolves
// nothing about the requested resource, so the same page is returned whether or
// not the requested AgentRun exists, and it issues no session or login-state
// cookie. Any cookie the caller already cleared on w is preserved. HEAD gets
// the same status and headers with no body.
func (a *Authenticator) renderSignInPage(w http.ResponseWriter, r *http.Request, returnURL string, signedOut bool) {
	data := signInPageData{
		Title:         "Sign in · NVT Agent",
		Heading:       "Sign in",
		Message:       "Sign in to open the NVT Agent gateway.",
		SignInURL:     a.signInURL(returnURL),
		BrandMarkPath: a.mountedPath(brandMarkPath),
		TouchIconPath: a.mountedPath(brandTouchIconPath),
		FaviconPath:   a.mountedPath(brandFaviconPath),
	}
	if signedOut {
		data.Title = "Signed out · NVT Agent"
		data.Heading = "Signed out"
		// State plainly that this was a local sign-out. The identity provider
		// session is untouched and may complete the next sign-in without a
		// prompt, which otherwise looks like the sign-out failed.
		data.Message = "Your gateway session has ended. Your identity provider may still have an active " +
			"session, so signing in again can complete without asking for credentials."
	}
	var body bytes.Buffer
	if err := signInTemplate.Execute(&body, data); err != nil {
		http.Error(w, "render sign-in page", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(body.Len()))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(body.Bytes())
}

// signInURL targets the mounted login endpoint. The origin is never derived
// from the request: forwarding headers are attacker-controlled, and using them
// would let a spoofed X-Forwarded-Host become the target of the control itself.
// A configured PublicURL is trusted operator configuration, so it keeps
// pointing central login at one stable origin in subdomain mode and carries the
// mounted base path in path mode. Without it, the control stays relative to the
// origin the browser already reached, which no header can redirect.
func (a *Authenticator) signInURL(returnURL string) string {
	query := "?return_url=" + url.QueryEscape(returnURL)
	if trusted := strings.TrimRight(a.config.PublicURL, "/"); trusted != "" {
		return trusted + "/oauth2/login" + query
	}
	return a.mountedPath("/oauth2/login") + query
}

// requestReturnURL keeps the originally requested path and query so an explicit
// sign-in lands where the user was going. The candidate goes through the same
// validation the login endpoint applies, and anything it rejects falls back to
// the mounted dashboard root, so no request can widen the redirect target.
func (a *Authenticator) requestReturnURL(r *http.Request) string {
	if returnURL, ok := a.validateReturnURL(a.safeReturnURL(r), r); ok {
		return returnURL
	}
	return a.mountedPath("/")
}
