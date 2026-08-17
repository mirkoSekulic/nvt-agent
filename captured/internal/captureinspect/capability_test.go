package captureinspect

import (
	"bufio"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
)

func TestCapabilityHintFromConnectMatchesExplicitProxyContract(t *testing.T) {
	request := func(headers string) *http.Request {
		value, err := http.ReadRequest(bufio.NewReader(strings.NewReader("CONNECT api.github.com:443 HTTP/1.1\r\nHost: api.github.com:443\r\n" + headers + "\r\n")))
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	for name, test := range map[string]struct {
		headers, want string
		valid         bool
	}{
		"header":         {headers: "X-NVT-Capability: github-main-app\r\n", want: "github-main-app", valid: true},
		"proxy username": {headers: "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("codex-main:discarded-secret")) + "\r\n", want: "codex-main", valid: true},
		"none":           {valid: true},
		"duplicate":      {headers: "X-NVT-Capability: one\r\nX-NVT-Capability: two\r\n"},
		"conflicting":    {headers: "X-NVT-Capability: one\r\nProxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("two:secret")) + "\r\n"},
	} {
		t.Run(name, func(t *testing.T) {
			got, valid := CapabilityHintFromConnect(request(test.headers))
			if got != test.want || valid != test.valid {
				t.Fatalf("hint=%q valid=%t", got, valid)
			}
		})
	}
}
