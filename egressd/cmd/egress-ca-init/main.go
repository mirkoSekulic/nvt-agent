package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/mirkoSekulic/nvt-agent/egressd/internal/egress"
)

type repeatedStrings []string

func (values *repeatedStrings) String() string {
	return fmt.Sprint([]string(*values))
}

func (values *repeatedStrings) Set(value string) error {
	*values = append(*values, value)
	return nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "egress-ca-init: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	flags := flag.NewFlagSet("egress-ca-init", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	certFile := flags.String("cert-file", "", "path to write ca.crt")
	keyFile := flags.String("key-file", "", "path to write ca.key")
	var leafDNSNames repeatedStrings
	var upstreamLeafNames repeatedStrings
	flags.Var(&leafDNSNames, "leaf-dns-name", "additional local/synthetic DNS name the CA may mint")
	flags.Var(&upstreamLeafNames, "upstream-leaf-name", "forward-proxy upstream DNS name the CA may mint")
	if err := flags.Parse(args); err != nil {
		return err
	}

	if *certFile == "" || *keyFile == "" {
		return fmt.Errorf("usage: egress-ca-init --cert-file PATH --key-file PATH [--leaf-dns-name NAME ...] [--upstream-leaf-name NAME ...]")
	}
	certExists := fileExists(*certFile)
	keyExists := fileExists(*keyFile)
	rotationMarker := *keyFile + ".rotation"
	if fileExists(rotationMarker) {
		if os.Getenv("NVT_EGRESS_CA_CHECK_ONLY") == "1" {
			fmt.Fprintln(os.Stdout, "renewal-required")
			return nil
		}
		return rotateCA(*certFile, *keyFile, rotationMarker, []string(leafDNSNames), []string(upstreamLeafNames), "recover interrupted rotation")
	}
	if certExists || keyExists {
		if !certExists || !keyExists {
			return fmt.Errorf("durable CA is incomplete; remove both files and retry")
		}
		if _, err := egress.LoadCAWithUpstreams(*certFile, *keyFile, []string(leafDNSNames), []string(upstreamLeafNames)); errors.Is(err, egress.ErrCARenewalRequired) {
			if os.Getenv("NVT_EGRESS_CA_CHECK_ONLY") == "1" {
				fmt.Fprintln(os.Stdout, "renewal-required")
				return nil
			}
			return rotateCA(*certFile, *keyFile, rotationMarker, []string(leafDNSNames), []string(upstreamLeafNames), fmt.Sprintf("certificate entered the %s renewal window", egress.CARenewalMargin))
		} else if err != nil {
			return fmt.Errorf("existing durable CA does not match configured names; delete the egress-ca directory to rotate it: %w", err)
		}
		return nil
	}
	ca, err := egress.NewCAWithUpstreams([]string(leafDNSNames), []string(upstreamLeafNames))
	if err != nil {
		return fmt.Errorf("generate CA: %w", err)
	}
	if err := ca.WriteKeyPair(*certFile, *keyFile); err != nil {
		return fmt.Errorf("write CA: %w", err)
	}
	return nil
}

func rotateCA(certFile, keyFile, marker string, leafDNSNames, upstreamLeafNames []string, reason string) error {
	if err := os.WriteFile(marker, []byte("rotation-in-progress\n"), 0o600); err != nil {
		return fmt.Errorf("write CA rotation marker: %w", err)
	}
	ca, err := egress.NewCAWithUpstreams(leafDNSNames, upstreamLeafNames)
	if err != nil {
		return fmt.Errorf("generate replacement CA: %w", err)
	}
	if err := ca.WriteKeyPair(certFile, keyFile); err != nil {
		return fmt.Errorf("write replacement CA: %w", err)
	}
	if err := os.Remove(marker); err != nil {
		return fmt.Errorf("complete CA rotation: %w", err)
	}
	fmt.Fprintf(os.Stderr, "egress-ca-init: rotated durable CA (%s)\n", reason)
	return nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Size() > 0
}
