// git-wrapper is a hermetic test helper. It records the exact resolver process
// contract, then delegates to a real Git binary or injects a bounded failure.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

type config struct {
	RealGit      string `json:"real_git"`
	LogPath      string `json:"log_path"`
	Mode         string `json:"mode"`
	MutationPath string `json:"mutation_path"`
	PIDPath      string `json:"pid_path"`
}

type invocation struct {
	Arguments   []string `json:"arguments"`
	Environment []string `json:"environment"`
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--stubborn-child" {
		if err := os.WriteFile(os.Getenv("NVT_WRAPPER_CHILD_PID_PATH"), []byte(fmt.Sprintf("%d", os.Getpid())), 0o600); err != nil {
			os.Exit(91)
		}
		for {
			time.Sleep(time.Second)
		}
	}
	executable, err := os.Executable()
	if err != nil {
		os.Exit(90)
	}
	configurationBytes, err := os.ReadFile(executable + ".json")
	if err != nil {
		os.Exit(90)
	}
	var configuration config
	if json.Unmarshal(configurationBytes, &configuration) != nil {
		os.Exit(90)
	}
	if err := appendInvocation(configuration.LogPath, invocation{
		Arguments:   append([]string(nil), os.Args[1:]...),
		Environment: append([]string(nil), os.Environ()...),
	}); err != nil {
		os.Exit(90)
	}
	switch configuration.Mode {
	case "fail":
		for index := 0; index < 10000; index++ {
			fmt.Fprintln(os.Stderr, "REMOTE-SECRET-CANARY")
		}
		os.Exit(42)
	case "hang":
		_ = os.WriteFile(configuration.PIDPath, []byte(fmt.Sprintf("%d", os.Getpid())), 0o600)
		child := exec.Command(executable, "--stubborn-child")
		child.Env = append(os.Environ(), "NVT_WRAPPER_CHILD_PID_PATH="+configuration.PIDPath+".child")
		if child.Start() != nil {
			os.Exit(90)
		}
		for {
			time.Sleep(time.Second)
		}
	case "mismatch":
		if hasTail(os.Args[1:], "rev-parse", "--verify", "FETCH_HEAD") {
			fmt.Println(strings.Repeat("0", 40))
			return
		}
	case "wrong-type":
		if hasTail(os.Args[1:], "cat-file", "-t", "FETCH_HEAD") {
			fmt.Println("blob")
			return
		}
	case "oversized":
		if hasTail(os.Args[1:], "rev-parse", "--verify", "FETCH_HEAD") {
			fmt.Print(strings.Repeat("x", 5<<20))
			return
		}
	}

	command := exec.Command(configuration.RealGit, os.Args[1:]...)
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	command.Env = append(os.Environ(), "GIT_SSL_NO_VERIFY=1")
	err = command.Run()
	if configuration.Mode == "special-artifact" && err == nil && hasCommand(os.Args[1:], "checkout") {
		_ = os.Remove(configuration.MutationPath)
		if syscall.Mkfifo(configuration.MutationPath, 0o700) != nil {
			os.Exit(90)
		}
	}
	if err == nil {
		return
	}
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) {
		os.Exit(90)
	}
	os.Exit(exitError.ExitCode())
}

func appendInvocation(path string, value invocation) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	return json.NewEncoder(file).Encode(value)
}

func hasTail(arguments []string, tail ...string) bool {
	if len(arguments) < len(tail) {
		return false
	}
	for index := range tail {
		if arguments[len(arguments)-len(tail)+index] != tail[index] {
			return false
		}
	}
	return true
}

func hasCommand(arguments []string, command string) bool {
	for index := 0; index < len(arguments); index++ {
		if arguments[index] == command {
			return true
		}
	}
	return false
}
