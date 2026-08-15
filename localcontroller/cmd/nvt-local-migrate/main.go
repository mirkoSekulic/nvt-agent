package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/mirkoSekulic/nvt-agent/localcontroller/internal/migration"
)

func main() {
	var options migration.Options
	var output string
	var check bool
	flag.StringVar(&options.ManifestPath, "manifest", "", "absolute path to migration manifest")
	flag.StringVar(&options.AgentsRoot, "agents-root", "", "absolute path to .agents")
	flag.StringVar(&options.BrokerAgents, "broker-agents", "", "absolute path to broker agents.yaml")
	flag.StringVar(&options.BrokerConfig, "broker-config", "", "absolute path to broker.yaml")
	flag.StringVar(&output, "output", "", "absolute output path (stdout when omitted)")
	flag.BoolVar(&check, "check", false, "validate without writing generated configuration")
	flag.Parse()
	if check && output != "" {
		fmt.Fprintln(os.Stderr, "nvt-local-migrate: output failed")
		os.Exit(1)
	}
	encoded, err := migration.Generate(options)
	if err != nil {
		fmt.Fprintln(os.Stderr, "nvt-local-migrate: migration failed: invalid or unsupported configuration")
		os.Exit(1)
	}
	if check {
		clear(encoded)
		return
	}
	if output == "" {
		_, err = os.Stdout.Write(encoded)
	} else if !filepath.IsAbs(output) || filepath.Clean(output) != output {
		err = migration.ErrInvalidInput
	} else {
		err = writeAtomic(output, encoded)
	}
	clear(encoded)
	if err != nil {
		fmt.Fprintln(os.Stderr, "nvt-local-migrate: output failed")
		os.Exit(1)
	}
}

func writeAtomic(path string, data []byte) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".nvt-local-migrate-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}
