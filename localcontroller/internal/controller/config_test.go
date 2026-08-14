package controller

import (
	"testing"
	"time"
)

func TestValidateConfigBounds(t *testing.T) {
	valid := Config{Bind: "0.0.0.0:7480", StatePath: "/state/controller/local-controller.sqlite3", MaxActiveRuns: 32, MaxClaimLease: 30 * time.Second, SweepInterval: time.Second}
	if err := ValidateConfig(valid); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Config){
		"bind":  func(value *Config) { value.Bind = "7480" },
		"state": func(value *Config) { value.StatePath = "/state/data.db" },
		"relative state": func(value *Config) {
			value.StatePath = "state/local-controller.sqlite3"
		},
		"root state":  func(value *Config) { value.StatePath = "/local-controller.sqlite3" },
		"capacity":    func(value *Config) { value.MaxActiveRuns = 0 },
		"claim lease": func(value *Config) { value.MaxClaimLease = 0 },
		"sweep":       func(value *Config) { value.SweepInterval = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if err := ValidateConfig(candidate); err == nil {
				t.Fatal("invalid config accepted")
			}
		})
	}
}

func TestConfigEnvironmentIsStrictAndUsesDefaultsOnlyWhenOmitted(t *testing.T) {
	for _, name := range []string{
		"NVT_LOCAL_CONTROLLER_BIND",
		"NVT_LOCAL_CONTROLLER_STATE",
		"NVT_LOCAL_CONTROLLER_MAX_ACTIVE_RUNS",
		"NVT_LOCAL_CONTROLLER_MAX_CLAIM_LEASE_SECONDS",
		"NVT_LOCAL_CONTROLLER_SWEEP_SECONDS",
	} {
		t.Setenv(name, "")
		if _, err := ConfigFromEnvironment(); err == nil {
			t.Fatalf("explicitly empty %s was accepted", name)
		}
		t.Setenv(name, defaultEnvironmentValue(name))
	}
	config, err := ConfigFromEnvironment()
	if err != nil || config.MaxActiveRuns != 32 || config.MaxClaimLease != 30*time.Second || config.SweepInterval != time.Second {
		t.Fatalf("explicit valid environment = %#v, %v", config, err)
	}
}

func defaultEnvironmentValue(name string) string {
	switch name {
	case "NVT_LOCAL_CONTROLLER_BIND":
		return "0.0.0.0:7480"
	case "NVT_LOCAL_CONTROLLER_STATE":
		return "/state/controller/local-controller.sqlite3"
	case "NVT_LOCAL_CONTROLLER_MAX_ACTIVE_RUNS":
		return "32"
	case "NVT_LOCAL_CONTROLLER_MAX_CLAIM_LEASE_SECONDS":
		return "30"
	default:
		return "1"
	}
}
