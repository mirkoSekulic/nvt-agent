package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
)

func main() {
	output := flag.String("output", "", "bounded prompt-capture output")
	flag.Parse()
	if *output == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "nvt-guest-session-fixture: output is required")
		os.Exit(2)
	}
	file, err := os.OpenFile(*output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		fmt.Fprintln(os.Stderr, "nvt-guest-session-fixture: output is unavailable")
		os.Exit(1)
	}
	defer file.Close()
	scanner := bufio.NewScanner(os.Stdin)
	buffer := make([]byte, 4096)
	scanner.Buffer(buffer, 64*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) > 32*1024 {
			fmt.Fprintln(os.Stderr, "nvt-guest-session-fixture: input exceeds the bound")
			os.Exit(1)
		}
		if _, err := fmt.Fprintln(file, line); err != nil || file.Sync() != nil {
			fmt.Fprintln(os.Stderr, "nvt-guest-session-fixture: output failed")
			os.Exit(1)
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "nvt-guest-session-fixture: input failed")
		os.Exit(1)
	}
}
