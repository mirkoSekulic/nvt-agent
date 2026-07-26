package gateway

import (
	"bytes"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
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
	Title     string
	Heading   string
	Message   string
	SignInURL string
}

var signInTemplate = template.Must(template.New("signin").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{ .Title }}</title>
  <style>
    body { font-family: system-ui, sans-serif; margin: 2rem; color: #17202a; }
    main { max-width: 32rem; margin: 0 auto; }
    p { color: #43536b; line-height: 1.5; }
    a.signin { display: inline-block; margin-top: .5rem; border: 1px solid #0b66c3; border-radius: .35rem;
      background: #0b66c3; color: #ffffff; padding: .5rem 1rem; text-decoration: none; font-weight: 600; }
  </style>
</head>
<body>
  <main>
    <h1>{{ .Heading }}</h1>
    <p>{{ .Message }}</p>
    <p><a class="signin" href="{{ .SignInURL }}">Sign in</a></p>
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
		Title:     "Sign in",
		Heading:   "Sign in",
		Message:   "Sign in to open the nvt agent gateway.",
		SignInURL: a.signInURL(r, returnURL),
	}
	if signedOut {
		data.Title = "Signed out"
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

// signInURL targets the mounted login endpoint, matching the URL the gateway
// redirected to before sign-in became explicit. It works in both routing modes
// and under a mounted base path.
func (a *Authenticator) signInURL(r *http.Request, returnURL string) string {
	return a.publicBaseURL(r) + "/oauth2/login?return_url=" + url.QueryEscape(returnURL)
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
