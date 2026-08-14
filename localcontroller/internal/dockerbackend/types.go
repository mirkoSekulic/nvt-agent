package dockerbackend

import (
	"context"
	"io"
	"time"
)

const (
	ownerLabel  = "nvt.dev/local-controller-owner"
	runLabel    = "nvt.dev/local-run-id"
	digestLabel = "nvt.dev/local-run-digest"
)

type Config struct {
	DockerHost       string
	RunsDir          string
	BrokerURL        string
	BrokerCAFile     string
	BrokerAgentsPath string
	IdentityKeyPath  string
	Owner            string
	ExternalNetwork  string
	ProxyPort        int
	ProtectedCIDRs   string
	DindImage        string
	EgressdImage     string
	CapturedImage    string
	SeedImage        string
	OperationTimeout time.Duration
}

// CommandBoundary is the only Docker-specific authority used by the backend.
// Input may contain a broker identity only when seeding the private egress
// volume; implementations must never include it in arguments or output.
type CommandBoundary interface {
	Run(context.Context, io.Reader, ...string) ([]byte, error)
}

type identityTokens struct {
	agent  string
	egress string
}

type resourceNames struct {
	project       string
	composeFile   string
	agentConfig   string
	egressPrivate string
	egressPublic  string
	workspace     string
	home          string
	dockerData    string
	internalNet   string
	privateNet    string
}

type ownedLabels struct {
	Owner  string
	RunID  string
	Digest string
}
