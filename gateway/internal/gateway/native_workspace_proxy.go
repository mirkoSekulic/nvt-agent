package gateway

import (
	"context"
	"net"
	"net/http"
	"net/url"

	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment/workspacetunnel"
)

const nativeWorkspaceSyntheticAuthority = "native-workspace.invalid"

func nativeWorkspaceUpstreamURL() *url.URL {
	return &url.URL{Scheme: "http", Host: nativeWorkspaceSyntheticAuthority}
}

// nativeWorkspaceHTTPTransport has no proxy or ambient dialing path. The
// browser-controlled network/address arguments are intentionally ignored; the
// exact authenticated StreamOpener is the only route to the fixed guest-side
// loopback workspace configured outside AgentRun and browser input.
func nativeWorkspaceHTTPTransport(opener workspacetunnel.StreamOpener) *http.Transport {
	return &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return opener.OpenStream(ctx)
		},
		DisableKeepAlives: true,
		ForceAttemptHTTP2: false,
		MaxConnsPerHost:   1,
	}
}
