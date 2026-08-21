package dockerbackend

import (
	"encoding/json"
	"testing"

	"github.com/mirkoSekulic/nvt-agent/protocol/resolvedrun"
)

func TestLocalEgressdRenderingPreservesDomainPolicy(t *testing.T) {
	run := testMediatedRun(t)
	run.Egress.DomainPolicy = &resolvedrun.DomainPolicy{
		DefaultAction: "deny",
		Allow:         []string{"api.example.test", "github.example"},
		Deny:          []string{"pastebin.com"},
	}
	rendered, err := renderEgressdConfig(Config{BrokerURL: "http://broker:7347"}, run)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		ForwardProxy struct {
			AllowUnmatchedHosts bool `json:"allow_unmatched_hosts"`
			DomainPolicy        struct {
				DefaultAction string   `json:"default_action"`
				Allow         []string `json:"allow"`
				Deny          []string `json:"deny"`
			} `json:"domain_policy"`
		} `json:"forward_proxy"`
	}
	if err := json.Unmarshal(rendered, &document); err != nil {
		t.Fatal(err)
	}
	if document.ForwardProxy.AllowUnmatchedHosts || document.ForwardProxy.DomainPolicy.DefaultAction != "deny" ||
		len(document.ForwardProxy.DomainPolicy.Allow) != 2 || len(document.ForwardProxy.DomainPolicy.Deny) != 1 {
		t.Fatalf("rendered domain policy = %#v", document.ForwardProxy)
	}
}
