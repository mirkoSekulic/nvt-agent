package guestidentity

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
)

const (
	SessionCredentialSocketName  = "session-credential.sock"
	sessionCredentialIPCDeadline = 5 * time.Second
	maxSessionCredentialHandlers = 4
)

func SessionCredentialSocketPath(runtimeDirectory string) string {
	return filepath.Join(runtimeDirectory, SessionCredentialSocketName)
}

// ServeSessionCredentials exposes a same-daemon-UID issuance boundary. Both
// production callers independently require UID 0 before reaching this code.
// The request accepts no bearer, binding, audience, or endpoint input.
func ServeSessionCredentials(ctx context.Context, runtime *Runtime, runtimeDirectory string) error {
	if ctx == nil || runtime == nil || !validAbsoluteDirectory(runtimeDirectory) {
		return failure(ReasonStateInvalid, false, false)
	}
	ownerUID := uint32(os.Geteuid())
	if err := ensurePrivateDirectory(runtimeDirectory, ownerUID); err != nil {
		return failure(ReasonStateUnavailable, false, false)
	}
	socketPath := SessionCredentialSocketPath(runtimeDirectory)
	if info, err := os.Lstat(socketPath); err == nil {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 || stat.Uid != ownerUID {
			return failure(ReasonStateUnavailable, false, false)
		}
		if err := os.Remove(socketPath); err != nil {
			return failure(ReasonStateUnavailable, false, false)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return failure(ReasonStateUnavailable, false, false)
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		return failure(ReasonStateUnavailable, false, false)
	}
	listener.SetUnlinkOnClose(false)
	defer func() {
		_ = listener.Close()
		_ = os.Remove(socketPath)
	}()
	if err := os.Chmod(socketPath, 0o600); err != nil {
		return failure(ReasonStateUnavailable, false, false)
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = listener.Close()
		case <-done:
		}
	}()
	defer close(done)
	slots := make(chan struct{}, maxSessionCredentialHandlers)
	for {
		connection, acceptErr := listener.AcceptUnix()
		if acceptErr != nil {
			if ctx.Err() != nil || errors.Is(acceptErr, net.ErrClosed) {
				return nil
			}
			return failure(ReasonStateUnavailable, false, false)
		}
		select {
		case slots <- struct{}{}:
			go func() {
				defer func() { <-slots }()
				handleSessionCredentialConnection(ctx, runtime, connection, ownerUID)
			}()
		default:
			_ = connection.Close()
		}
	}
}

func handleSessionCredentialConnection(ctx context.Context, runtime *Runtime, connection *net.UnixConn, ownerUID uint32) {
	defer connection.Close()
	if peerUID, err := unixPeerUID(connection); err != nil || peerUID != ownerUID {
		return
	}
	deadline := time.Now().Add(sessionCredentialIPCDeadline)
	_ = connection.SetDeadline(deadline)
	reader := bufio.NewReader(io.LimitReader(connection, int64(guestenrollment.MaxNativeSessionLocalMessageBytes)+1))
	line, err := reader.ReadBytes('\n')
	if err != nil || len(line) == 0 || len(line) > guestenrollment.MaxNativeSessionLocalMessageBytes {
		zero(line)
		return
	}
	request, err := guestenrollment.DecodeNativeSessionCredentialRequest(line)
	zero(line)
	if err != nil {
		return
	}
	if _, trailingErr := reader.ReadByte(); !errors.Is(trailingErr, io.EOF) {
		return
	}
	_ = request
	operationContext, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	result, issueErr := runtime.IssueGuestSession(operationContext)
	response := guestenrollment.NativeSessionCredentialResponse{
		ContractVersion: guestenrollment.NativeSessionLocalVersion,
	}
	if issueErr == nil {
		response.Type = guestenrollment.NativeSessionCredentialResult
		response.Result = &result
	} else {
		reason, temporary, uncertain := FailureDetails(issueErr)
		response.Type = guestenrollment.NativeSessionCredentialError
		response.Error = &guestenrollment.NativeSessionLocalError{
			Reason: string(reason), Temporary: temporary, Uncertain: uncertain,
		}
	}
	encoded, encodeErr := guestenrollment.EncodeNativeSessionCredentialResponse(response)
	result.Credential.Opaque = ""
	if response.Result != nil {
		response.Result.Credential.Opaque = ""
	}
	if encodeErr != nil {
		zero(encoded)
		return
	}
	defer zero(encoded)
	_, _ = io.Copy(connection, bytes.NewReader(encoded))
}
