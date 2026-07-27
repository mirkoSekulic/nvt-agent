package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/mirkoSekulic/nvt-agent/hostbundle/install"
	"github.com/mirkoSekulic/nvt-agent/hostbundle/oci"
)

func main() {
	if effectiveUID() != 0 {
		fmt.Fprintln(os.Stderr, "nvt-host-bootstrap: native installation requires root")
		os.Exit(1)
	}
	repository := flag.String("repository", "", "exact public HTTPS OCI repository")
	digest := flag.String("digest", "", "exact sha256 OCI index digest")
	root := flag.String("root", "/opt/nvt", "native installation root")
	operatingSystem := flag.String("os", runtime.GOOS, "target operating system")
	architecture := flag.String("arch", runtime.GOARCH, "target architecture")
	timeout := flag.Duration("timeout", 10*time.Minute, "bounded acquisition timeout")
	flag.Parse()
	if flag.NArg() != 0 || *repository == "" || *digest == "" {
		fmt.Fprintln(os.Stderr, "nvt-host-bootstrap: repository and digest are required")
		os.Exit(2)
	}
	client, err := newOCIClient(*timeout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "nvt-host-bootstrap: invalid bootstrap configuration")
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	result, err := (install.Installer{Puller: client, Root: *root}).Install(ctx, oci.Source{
		Repository: *repository, Digest: *digest, OS: *operatingSystem, Architecture: *architecture,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "nvt-host-bootstrap: %s\n", err)
		os.Exit(1)
	}
	action := "installed"
	if result.Reused {
		action = "verified"
	}
	fmt.Printf("nvt-host-bootstrap: %s host bundle %s (%s)\n", action, result.Version, result.Digest)
}
