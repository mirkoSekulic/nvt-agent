package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/mirkoSekulic/nvt-agent/hostbundle/contract"
	"github.com/mirkoSekulic/nvt-agent/hostbundle/nativeegressipc"
)

const maxConfigBytes = 64 * 1024

var sessionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

type configuration struct {
	Version                    int      `json:"version"`
	PythonPath                 string   `json:"python_path"`
	TmuxPath                   string   `json:"tmux_path"`
	StateDir                   string   `json:"state_dir"`
	SocketPath                 string   `json:"socket_path"`
	Workspace                  string   `json:"workspace"`
	SessionName                string   `json:"session_name"`
	SessionReadinessPath       string   `json:"session_readiness_path"`
	EgressReadinessSocketPath  string   `json:"egress_readiness_socket_path,omitempty"`
	SessionStartupGraceSeconds int      `json:"session_startup_grace_seconds"`
	SessionCommand             []string `json:"session_command"`
}

func main() {
	configPath := flag.String("config", "/etc/nvt-agent/guest.json", "guest supervisor configuration")
	flag.Parse()
	if flag.NArg() != 0 {
		fatal("unexpected arguments")
	}
	config, releaseRoot, err := loadConfiguration(*configPath)
	if err != nil {
		fatal(err.Error())
	}
	if err := run(config, releaseRoot); err != nil {
		fatal(err.Error())
	}
}

func run(config configuration, releaseRoot string) error {
	if err := os.MkdirAll(config.StateDir, 0o700); err != nil || os.MkdirAll(filepath.Dir(config.SocketPath), 0o700) != nil {
		return errors.New("guest runtime directories are unavailable")
	}
	readinessPath := filepath.Join(config.StateDir, "guest-ready")
	markerPath := filepath.Join(config.StateDir, "agentd", "session-launched")
	_ = os.Remove(readinessPath)
	_ = os.Remove(markerPath)
	_ = killSession(config)

	agentdPath := filepath.Join(releaseRoot, "bin", "agentd")
	socketMode := "0600"
	if config.SessionReadinessPath != "" {
		socketMode = "0660"
	}
	agentd := exec.Command(config.PythonPath,
		agentdPath,
		"--socket", config.SocketPath,
		"--socket-mode", socketMode,
		"--state-dir", config.StateDir,
		"--session", config.SessionName,
		"--session-ready-marker", markerPath,
		"--session-startup-grace-seconds", strconv.Itoa(config.SessionStartupGraceSeconds),
	)
	agentd.Env = []string{
		"HOME=" + config.StateDir,
		"PATH=" + filepath.Dir(config.TmuxPath) + ":/usr/bin:/bin",
		"PYTHONDONTWRITEBYTECODE=1",
		"PYTHONNOUSERSITE=1",
	}
	agentd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	agentd.Stdout = os.Stdout
	agentd.Stderr = os.Stderr
	if err := agentd.Start(); err != nil {
		return errors.New("agentd could not be started")
	}
	agentdDone := make(chan struct{})
	go func() {
		_ = agentd.Wait()
		close(agentdDone)
	}()
	cleanup := func() {
		_ = os.Remove(readinessPath)
		_ = killSession(config)
		terminate(agentd, agentdDone)
	}
	defer cleanup()

	startupDeadline := time.Now().Add(30*time.Second + time.Duration(config.SessionStartupGraceSeconds)*time.Second)
	if err := waitForAgentd(config.SocketPath, startupDeadline, agentdDone); err != nil {
		return err
	}
	var egressLease net.Conn
	var egressLeaseDone <-chan struct{}
	if config.EgressReadinessSocketPath != "" {
		var err error
		egressLease, err = waitForEgressReadiness(config.EgressReadinessSocketPath, time.Now().Add(90*time.Second), agentdDone)
		if err != nil {
			return err
		}
		defer egressLease.Close()
		closed := make(chan struct{})
		egressLeaseDone = closed
		go func() { nativeegressipc.WaitClosed(egressLease); close(closed) }()
	}
	command := resolveReleaseCommand(config.SessionCommand, releaseRoot)
	arguments := []string{"new-session", "-d", "-s", config.SessionName, "-c", config.Workspace, "--"}
	arguments = append(arguments, command...)
	session := exec.Command(config.TmuxPath, arguments...)
	session.Env = []string{"HOME=" + config.StateDir, "PATH=/usr/bin:/bin"}
	if output, err := session.CombinedOutput(); err != nil || len(output) > 4096 {
		return errors.New("guest session could not be started")
	}
	stableUntil := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(stableUntil) {
		if !sessionExists(config) {
			return errors.New("guest session exited during startup")
		}
		select {
		case <-agentdDone:
			return errors.New("agentd exited during startup")
		case <-time.After(50 * time.Millisecond):
		}
	}
	if err := atomicWrite(markerPath, []byte(strconv.FormatInt(time.Now().UnixNano(), 10)+"\n"), 0o600); err != nil {
		return errors.New("guest session readiness marker could not be published")
	}
	graceDeadline := time.Now().Add(time.Duration(config.SessionStartupGraceSeconds) * time.Second)
	for time.Now().Before(graceDeadline) {
		if !sessionExists(config) {
			return errors.New("guest session exited before readiness")
		}
		select {
		case <-agentdDone:
			return errors.New("agentd exited before readiness")
		case <-time.After(50 * time.Millisecond):
		}
	}
	if err := waitForAgentd(config.SocketPath, startupDeadline, agentdDone); err != nil {
		return err
	}
	if config.SessionReadinessPath != "" {
		if err := waitForSessionReadiness(config, time.Now().Add(90*time.Second), agentdDone); err != nil {
			return err
		}
	}
	if err := atomicWrite(readinessPath, []byte("ready\n"), 0o600); err != nil {
		return errors.New("guest readiness could not be published")
	}

	signals := make(chan os.Signal, 1)
	signalNotify(signals)
	defer signal.Stop(signals)
	sessionMonitor := time.NewTicker(250 * time.Millisecond)
	defer sessionMonitor.Stop()
	for {
		select {
		case <-signals:
			return nil
		case <-agentdDone:
			return errors.New("agentd exited unexpectedly")
		case <-egressLeaseDone:
			return errors.New("native egress capture exited unexpectedly")
		case <-sessionMonitor.C:
			if !sessionExists(config) {
				return errors.New("guest session exited unexpectedly")
			}
			if config.SessionReadinessPath != "" && !sessionTransportReady(config.SessionReadinessPath) {
				return errors.New("native session transport exited unexpectedly")
			}
		}
	}
}

func loadConfiguration(path string) (configuration, string, error) {
	data, err := os.ReadFile(path)
	if err != nil || len(data) > maxConfigBytes {
		return configuration{}, "", errors.New("guest supervisor configuration is unavailable")
	}
	var config configuration
	if contract.DecodeStrict(data, maxConfigBytes, &config) != nil {
		return configuration{}, "", errors.New("guest supervisor configuration is invalid")
	}
	if config.Version != 1 || !absoluteRegularExecutable(config.PythonPath) || !absoluteRegularExecutable(config.TmuxPath) || !validAbsoluteDirectory(config.StateDir) || !validAbsolutePath(config.SocketPath) || !validSessionReadinessPath(config) || !validEgressReadinessPath(config) || !validAbsoluteDirectory(config.Workspace) || !sessionPattern.MatchString(config.SessionName) || config.SessionStartupGraceSeconds < 0 || config.SessionStartupGraceSeconds > 30 || len(config.SessionCommand) == 0 || len(config.SessionCommand) > 32 {
		return configuration{}, "", errors.New("guest supervisor configuration is invalid")
	}
	argumentBytes := 0
	for _, argument := range config.SessionCommand {
		argumentBytes += len(argument)
		if argument == "" || strings.ContainsRune(argument, 0) || len(argument) > 4096 || argumentBytes > 16*1024 {
			return configuration{}, "", errors.New("guest supervisor session command is invalid")
		}
	}
	executable, err := os.Executable()
	if err != nil {
		return configuration{}, "", errors.New("guest release location is unavailable")
	}
	releaseRoot := filepath.Dir(filepath.Dir(executable))
	resolved := resolveReleaseCommand(config.SessionCommand, releaseRoot)
	if !absoluteRegularExecutable(resolved[0]) {
		return configuration{}, "", errors.New("guest supervisor session executable is unavailable")
	}
	if info, err := os.Stat(config.Workspace); err != nil || !info.IsDir() {
		return configuration{}, "", errors.New("guest workspace is unavailable")
	}
	return config, releaseRoot, nil
}

func validSessionReadinessPath(config configuration) bool {
	return config.SessionReadinessPath == "" ||
		(validAbsolutePath(config.SessionReadinessPath) && config.SessionReadinessPath != config.SocketPath)
}

func validEgressReadinessPath(config configuration) bool {
	return config.EgressReadinessSocketPath == "" ||
		(validAbsolutePath(config.EgressReadinessSocketPath) && config.EgressReadinessSocketPath != config.SocketPath &&
			config.EgressReadinessSocketPath != config.SessionReadinessPath)
}

func waitForEgressReadiness(path string, deadline time.Time, done <-chan struct{}) (net.Conn, error) {
	client := nativeegressipc.Client{SocketPath: path, OwnerUID: trustedReadinessOwnerUID(), Shared: true}
	for time.Now().Before(deadline) {
		select {
		case <-done:
			return nil, errors.New("agentd exited before native egress readiness")
		default:
		}
		if nativeegressipc.ValidateReadinessSocket(path, trustedReadinessOwnerUID()) != nil {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		attempt, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		connection, _, err := client.OpenHealth(attempt)
		cancel()
		if err == nil {
			return connection, nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return nil, errors.New("native egress readiness timed out")
}

func waitForSessionReadiness(config configuration, deadline time.Time, done <-chan struct{}) error {
	for time.Now().Before(deadline) {
		select {
		case <-done:
			return errors.New("agentd exited before native session readiness")
		default:
		}
		if !sessionExists(config) {
			return errors.New("guest session exited before native session readiness")
		}
		if sessionTransportReady(config.SessionReadinessPath) {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return errors.New("native session readiness timed out")
}

func sessionTransportReady(path string) bool {
	content, err := os.ReadFile(path)
	return err == nil && string(content) == "ready\n"
}

func resolveReleaseCommand(command []string, releaseRoot string) []string {
	resolved := append([]string(nil), command...)
	if strings.HasPrefix(resolved[0], "@release/") {
		resolved[0] = filepath.Join(releaseRoot, strings.TrimPrefix(resolved[0], "@release/"))
	}
	return resolved
}

func waitForAgentd(socketPath string, deadline time.Time, done <-chan struct{}) error {
	for time.Now().Before(deadline) {
		select {
		case <-done:
			return errors.New("agentd exited before readiness")
		default:
		}
		connection, err := net.DialTimeout("unix", socketPath, 200*time.Millisecond)
		if err == nil {
			_ = connection.SetDeadline(time.Now().Add(500 * time.Millisecond))
			_, writeErr := connection.Write([]byte("{\"type\":\"health\"}\n"))
			line, readErr := bufio.NewReader(io.LimitReader(connection, 4096)).ReadString('\n')
			connection.Close()
			if writeErr == nil && readErr == nil && strings.Contains(line, `"status":"ready"`) {
				return nil
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return errors.New("agentd readiness timed out")
}

func sessionExists(config configuration) bool {
	command := exec.Command(config.TmuxPath, "has-session", "-t", config.SessionName)
	command.Env = []string{"HOME=" + config.StateDir, "PATH=/usr/bin:/bin"}
	return command.Run() == nil
}

func killSession(config configuration) error {
	command := exec.Command(config.TmuxPath, "kill-session", "-t", config.SessionName)
	command.Env = []string{"HOME=" + config.StateDir, "PATH=/usr/bin:/bin"}
	_ = command.Run()
	return nil
}

func terminate(command *exec.Cmd, done <-chan struct{}) {
	if command.Process == nil {
		return
	}
	_ = syscall.Kill(-command.Process.Pid, syscall.SIGTERM)
	select {
	case <-done:
		return
	case <-time.After(5 * time.Second):
	}
	_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
	}
}

func atomicWrite(path string, content []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".nvt-*.tmp")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func absoluteRegularExecutable(path string) bool {
	if !validAbsolutePath(path) {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0
}

func validAbsoluteDirectory(path string) bool {
	return validAbsolutePath(path) && path != "/"
}

func validAbsolutePath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.ContainsRune(path, 0)
}

func fatal(message string) {
	fmt.Fprintf(os.Stderr, "nvt-guest-supervisor: %s\n", message)
	os.Exit(1)
}

// Small wrappers keep platform-specific imports out of the lifecycle flow.
var signalNotify = func(channel chan<- os.Signal) {
	signal.Notify(channel, syscall.SIGINT, syscall.SIGTERM)
}
