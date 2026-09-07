package manifest

import (
	"errors"
	"github.com/mirkoSekulic/nvt-agent/protocol/resolvedrun"
	"net/url"
)

func validatePiRuntime(r Runtime, providers map[string]BrokerProvider) error {
	selection := resolvedrun.Runtime{Type: r.Preset, Autonomy: r.Autonomy, Model: r.Model, Effort: r.Effort, CredentialProvider: r.CredentialProvider, Pi: r.Pi}
	if err := resolvedrun.ValidatePiSelection(selection); err != nil {
		return err
	}
	if r.Preset != "pi" {
		return nil
	}
	p, ok := providers[r.CredentialProvider]
	if !ok || p.Plugin != "token" || p.Mediation.Git || p.Mediation.Materialization != "header-inject" || r.Account != "" {
		return errors.New("Pi requires a separate static-token API provider binding")
	}
	u, _ := url.Parse(r.Pi.BaseURL)
	for _, host := range p.Mediation.Hosts {
		if host == u.Hostname() {
			return nil
		}
	}
	return errors.New("Pi endpoint is not authorized by its model provider")
}
