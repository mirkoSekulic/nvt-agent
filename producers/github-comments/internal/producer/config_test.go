package producer

import "testing"

func TestConfigDefaultOperatorCallbackBaseURL(t *testing.T) {
	cfg := Config{
		Repositories: []Repository{{Owner: "acme", Name: "widget"}},
		GitHubApp: GitHubAppConfig{
			AppID:          123,
			InstallationID: 456,
			PrivateKeyPath: "/tmp/key.pem",
		},
		AgentRun: AgentRunConfig{
			Namespace:    "nvt",
			RuntimeImage: "runtime:latest",
		},
	}
	if err := cfg.ApplyDefaultsAndValidate(); err != nil {
		t.Fatal(err)
	}
	if cfg.OperatorCallbackBaseURL != defaultOperatorCallbackBaseURL {
		t.Fatalf("OperatorCallbackBaseURL = %q, want %q", cfg.OperatorCallbackBaseURL, defaultOperatorCallbackBaseURL)
	}
}
