package controller

import (
	"testing"
	"time"
)

func TestValidateConfigBounds(t *testing.T) {
	valid := validControllerConfigForTest()
	if err := ValidateConfig(valid); err != nil {
		t.Fatal(err)
	}
	mixedFamily := valid
	mixedFamily.ProtectedCIDRs = "10.0.0.0/8 fd00:1234::/48"
	if err := ValidateConfig(mixedFamily); err != nil {
		t.Fatalf("mixed-family protected CIDRs rejected: %v", err)
	}
	testInvalidConfigMutations(t, valid)
}

func validControllerConfigForTest() Config {
	return Config{
		Bind: "0.0.0.0:7480", StatePath: "/state/controller/local-controller.sqlite3", MaxActiveRuns: 32,
		MaxClaimLease: 180 * time.Second, SweepInterval: time.Second, ReconcileInterval: time.Second,
		DockerHost: "unix:///var/run/docker.sock", RunsDir: "/state/controller/runs", BrokerURL: "http://broker:7347",
		BrokerAgentsPath: "/broker-state/agents.yaml", IdentityKeyPath: "/broker-state/local-controller.key",
		AdminTokenFile: "/broker-state/local-controller-admin-token", RouteTokenFile: "/broker-state/local-controller-route-token",
		ControllerOwner: "nvt-local-controller", ExternalNetwork: "agents-proxy", RunNetworkPool: "100.64.0.0/10", ProxyPort: 4090, DindImage: "nvt-dind:latest",
		ProtectedCIDRs: "127.0.0.0/8 169.254.0.0/16",
		EgressdImage:   "nvt-egressd:latest", CapturedImage: "nvt-captured:latest", SeedImage: "nvt-agent-runtime:latest",
		BackendOperationTimeout: 2 * time.Minute,
	}
}

func testInvalidConfigMutations(t *testing.T, valid Config) {
	t.Helper()
	for name, mutate := range map[string]func(*Config){
		"bind":  func(value *Config) { value.Bind = "7480" },
		"state": func(value *Config) { value.StatePath = "/state/data.db" },
		"relative state": func(value *Config) {
			value.StatePath = "state/local-controller.sqlite3"
		},
		"root state":                           func(value *Config) { value.StatePath = "/local-controller.sqlite3" },
		"capacity":                             func(value *Config) { value.MaxActiveRuns = 0 },
		"claim lease":                          func(value *Config) { value.MaxClaimLease = 0 },
		"claim shorter than backend operation": func(value *Config) { value.MaxClaimLease = value.BackendOperationTimeout + 29*time.Second },
		"managed network overlap":              func(value *Config) { value.RunNetworkPool = "172.30.0.0/15" },
		"protected network overlap":            func(value *Config) { value.ProtectedCIDRs = "100.64.0.0/10" },
		"malformed protected network":          func(value *Config) { value.ProtectedCIDRs = "not-a-prefix" },
		"network capacity":                     func(value *Config) { value.RunNetworkPool = "100.64.0.0/27" },
		"sweep":                                func(value *Config) { value.SweepInterval = 0 },
		"reconcile":                            func(value *Config) { value.ReconcileInterval = 0 },
		"docker host":                          func(value *Config) { value.DockerHost = "" },
		"runs dir":                             func(value *Config) { value.RunsDir = "relative" },
		"broker agents":                        func(value *Config) { value.BrokerAgentsPath = "relative" },
		"route domain":                         func(value *Config) { value.RouteBaseDomain = "Bad.Domain" },
		"route prefix":                         func(value *Config) { value.RoutePathPrefix = "/agents/../other" },
		"gateway container":                    func(value *Config) { value.GatewayContainer = "local gateway" },
		"scheduling path":                      func(value *Config) { value.SchedulingConfigPath = "relative.json" },
		"missing route token":                  func(value *Config) { value.RouteTokenFile = "" },
		"relative route token":                 func(value *Config) { value.RouteTokenFile = "relative-token" },
		"relative admin token":                 func(value *Config) { value.AdminTokenFile = "relative-token" },
		"malformed route token":                func(value *Config) { value.RouteTokenFile = "/run/secrets/route\ntoken" },
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
		"NVT_LOCAL_CONTROLLER_RECONCILE_SECONDS",
		"NVT_LOCAL_CONTROLLER_BACKEND_TIMEOUT_SECONDS",
		"NVT_LOCAL_CONTROLLER_PROXY_PORT",
		"NVT_LOCAL_CONTROLLER_RUN_NETWORK_POOL",
		"NVT_LOCAL_CONTROLLER_ROUTE_BASE_DOMAIN",
		"NVT_LOCAL_CONTROLLER_ROUTE_PATH_PREFIX",
		"NVT_LOCAL_CONTROLLER_GATEWAY_CONTAINER",
		"NVT_LOCAL_CONTROLLER_ROUTE_TOKEN_FILE",
	} {
		t.Setenv(name, "")
		if _, err := ConfigFromEnvironment(); err == nil {
			t.Fatalf("explicitly empty %s was accepted", name)
		}
		t.Setenv(name, defaultEnvironmentValue(name))
	}
	config, err := ConfigFromEnvironment()
	if err != nil || config.MaxActiveRuns != 32 || config.MaxClaimLease != 180*time.Second || config.SweepInterval != time.Second {
		t.Fatalf("explicit valid environment = %#v, %v", config, err)
	}
}

func TestLocalControllerActiveRunLimitMatchesRouteContract(t *testing.T) {
	valid := validControllerConfigForTest()
	valid.MaxActiveRuns = 500
	if err := ValidateConfig(valid); err != nil {
		t.Fatalf("route maximum rejected: %v", err)
	}
	valid.MaxActiveRuns = 501
	if err := ValidateConfig(valid); err == nil {
		t.Fatal("active-run count above route contract accepted")
	}
}

func TestDockerBackendEnvironmentRejectsMalformedPathsAndEndpoints(t *testing.T) {
	for name, value := range map[string]string{
		"NVT_LOCAL_CONTROLLER_DOCKER_HOST":       "",
		"NVT_LOCAL_CONTROLLER_RUNS_DIR":          "relative/runs",
		"NVT_LOCAL_CONTROLLER_BROKER_AGENTS":     "relative/agents.yaml",
		"NVT_LOCAL_CONTROLLER_IDENTITY_KEY_FILE": "relative/key",
		"NVT_LOCAL_CONTROLLER_BROKER_CA_FILE":    "relative/ca.crt",
		"NVT_LOCAL_CONTROLLER_BROKER_URL":        "http://user@example.test",
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, value)
			if _, err := ConfigFromEnvironment(); err == nil {
				t.Fatal("malformed backend configuration was accepted")
			}
		})
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
		return "180"
	case "NVT_LOCAL_CONTROLLER_BACKEND_TIMEOUT_SECONDS":
		return "120"
	case "NVT_LOCAL_CONTROLLER_PROXY_PORT":
		return "4090"
	case "NVT_LOCAL_CONTROLLER_RUN_NETWORK_POOL":
		return "100.64.0.0/10"
	case "NVT_LOCAL_CONTROLLER_ROUTE_BASE_DOMAIN":
		return "agent.localhost"
	case "NVT_LOCAL_CONTROLLER_ROUTE_PATH_PREFIX":
		return "/agents"
	case "NVT_LOCAL_CONTROLLER_GATEWAY_CONTAINER":
		return "nvt-local-gateway"
	case "NVT_LOCAL_CONTROLLER_ROUTE_TOKEN_FILE":
		return "/broker-state/local-controller-route-token"
	default:
		return "1"
	}
}
