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

// ServeSessionCredentials exposes the established same-daemon-UID credential
// issuance boundary. Production callers independently require UID 0 before
// reaching this code. Purpose-separated requests accept no bearer, binding,
// audience, endpoint, target, or provider input.
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
	maximum := guestenrollment.MaxNativeSessionLocalMessageBytes
	if guestenrollment.MaxNativeEgressLocalMessageBytes > maximum {
		maximum = guestenrollment.MaxNativeEgressLocalMessageBytes
	}
	reader := bufio.NewReader(io.LimitReader(connection, int64(maximum)+1))
	line, err := reader.ReadBytes('\n')
	if err != nil || len(line) == 0 || len(line) > maximum {
		zero(line)
		return
	}
	_, sessionRequestErr := guestenrollment.DecodeNativeSessionCredentialRequest(line)
	_, egressRequestErr := guestenrollment.DecodeNativeEgressCredentialRequest(line)
	zero(line)
	if (sessionRequestErr == nil) == (egressRequestErr == nil) {
		return
	}
	if _, trailingErr := reader.ReadByte(); !errors.Is(trailingErr, io.EOF) {
		return
	}
	operationContext, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	if sessionRequestErr == nil {
		handleGuestSessionCredentialRequest(operationContext, runtime, connection)
		return
	}
	handleNativeEgressCredentialRequest(operationContext, runtime, connection)
}

func handleGuestSessionCredentialRequest(ctx context.Context, runtime *Runtime, connection net.Conn) {
	result, issueErr := runtime.IssueGuestSession(ctx)
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

func handleNativeEgressCredentialRequest(ctx context.Context, runtime *Runtime, connection net.Conn) {
	result, issueErr := runtime.IssueNativeEgress(ctx)
	response := guestenrollment.NativeEgressCredentialResponse{
		ContractVersion: guestenrollment.NativeEgressLocalVersion,
	}
	if issueErr == nil {
		response.Type = guestenrollment.NativeEgressCredentialResult
		response.Result = &result
	} else {
		reason, temporary, uncertain := FailureDetails(issueErr)
		response.Type = guestenrollment.NativeEgressCredentialError
		response.Error = &guestenrollment.NativeEgressLocalError{
			Reason: string(reason), Temporary: temporary, Uncertain: uncertain,
		}
	}
	encoded, encodeErr := guestenrollment.EncodeNativeEgressCredentialResponse(response)
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
