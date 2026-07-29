package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/mirkoSekulic/nvt-agent/hostbundle/bundle"
	"github.com/mirkoSekulic/nvt-agent/hostbundle/contract"
	"github.com/mirkoSekulic/nvt-agent/hostbundle/oci"
)

func main() {
	version := flag.String("version", "", "coordinated bundle version")
	buildID := flag.String("build-id", "", "full source revision")
	architecture := flag.String("arch", "amd64", "target architecture")
	archive := flag.String("archive", "", "output tar.gz")
	layout := flag.String("layout", "", "output OCI layout")
	tag := flag.String("tag", "", "OCI discovery tag")
	source := flag.String("source", "", "OCI source annotation")
	supervisor := flag.String("supervisor", "", "compiled guest supervisor")
	identityDaemon := flag.String("identity-daemon", "", "compiled guest runtime identity daemon")
	sessionDaemon := flag.String("session-daemon", "", "compiled native guest session daemon")
	bootstrap := flag.String("bootstrap", "", "compiled bootstrap for future updates")
	sessionFixture := flag.String("session-fixture", "", "compiled bounded session fixture")
	agentd := flag.String("agentd", "", "agentd source")
	agentdctl := flag.String("agentdctl", "", "agentdctl source")
	service := flag.String("service", "", "systemd service unit")
	identityService := flag.String("identity-service", "", "guest runtime identity systemd service unit")
	sessionService := flag.String("session-service", "", "native guest session systemd service unit")
	config := flag.String("config", "", "example guest supervisor config")
	identityConfig := flag.String("identity-config", "", "example guest runtime identity config")
	sessionConfig := flag.String("session-config", "", "example native guest session config")
	workspaceSessionConfig := flag.String("workspace-session-config", "", "example native guest session config with workspace forwarding")
	flag.Parse()
	if flag.NArg() != 0 || *version == "" || *buildID == "" || *archive == "" || *layout == "" || *tag == "" || *source == "" {
		fmt.Fprintln(os.Stderr, "nvt-host-bundle-builder: all release/output flags are required")
		os.Exit(2)
	}
	inputs := []bundle.InputFile{
		{Path: "bin/nvt-guest-supervisor", Source: *supervisor, Mode: 0o755},
		{Path: "bin/nvt-guest-identityd", Source: *identityDaemon, Mode: 0o755},
		{Path: "bin/nvt-guest-sessiond", Source: *sessionDaemon, Mode: 0o755},
		{Path: "bin/nvt-host-bootstrap", Source: *bootstrap, Mode: 0o755},
		{Path: "bin/nvt-guest-session-fixture", Source: *sessionFixture, Mode: 0o755},
		{Path: "bin/agentd", Source: *agentd, Mode: 0o755},
		{Path: "bin/agentdctl", Source: *agentdctl, Mode: 0o755},
		{Path: "share/systemd/nvt-agent-guest.service", Source: *service, Mode: 0o644},
		{Path: "share/systemd/nvt-guest-identity.service", Source: *identityService, Mode: 0o644},
		{Path: "share/systemd/nvt-guest-session.service", Source: *sessionService, Mode: 0o644},
		{Path: "share/examples/guest.json", Source: *config, Mode: 0o644},
		{Path: "share/examples/identity.json", Source: *identityConfig, Mode: 0o644},
		{Path: "share/examples/session.json", Source: *sessionConfig, Mode: 0o644},
		{Path: "share/examples/session-workspace.json", Source: *workspaceSessionConfig, Mode: 0o644},
	}
	if err := os.MkdirAll(filepath.Dir(*archive), 0o755); err != nil {
		fatal("create output directory")
	}
	manifest := contract.Manifest{
		ContractVersion:  contract.Version,
		OS:               "linux",
		Architecture:     *architecture,
		BundleVersion:    *version,
		BuildID:          *buildID,
		NativeEntrypoint: "bin/nvt-guest-supervisor",
		ServiceIdentity:  "nvt-agent-guest.service",
		Compatibility: contract.Compatibility{
			AgentdProtocol: contract.AgentdProtocolVersion, NativeSessionProtocol: contract.NativeSessionProtocolVersion,
			NativeWorkspaceProtocol: contract.NativeWorkspaceProtocolVersion,
		},
	}
	if _, err := bundle.BuildArchive(*archive, manifest, inputs); err != nil {
		fatal(err.Error())
	}
	if err := os.RemoveAll(*layout); err != nil {
		fatal("clear OCI layout")
	}
	digest, err := oci.BuildLayout(*layout, *tag, *archive, "linux", *architecture, map[string]string{
		"org.opencontainers.image.source":   *source,
		"org.opencontainers.image.revision": *buildID,
		"org.opencontainers.image.version":  *version,
	})
	if err != nil {
		fatal(err.Error())
	}
	fmt.Println(digest)
}

func fatal(message string) {
	fmt.Fprintf(os.Stderr, "nvt-host-bundle-builder: %s\n", message)
	os.Exit(1)
}
