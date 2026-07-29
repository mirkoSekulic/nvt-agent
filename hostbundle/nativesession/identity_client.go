package nativesession

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"time"

	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
)

const identityOperationTimeout = 5 * time.Second

type IdentityClient struct {
	SocketPath string
	Dial       func(context.Context, string, string) (net.Conn, error)
}

func (client *IdentityClient) Issue(ctx context.Context) (guestenrollment.GuestSessionIssueResult, error) {
	if client == nil || ctx == nil || !validFile(client.SocketPath) {
		return guestenrollment.GuestSessionIssueResult{}, fail(ReasonConfiguration, false, false)
	}
	request, err := guestenrollment.EncodeNativeSessionCredentialRequest(guestenrollment.NativeSessionCredentialRequest{
		ContractVersion: guestenrollment.NativeSessionLocalVersion,
		Type:            guestenrollment.NativeSessionCredentialIssue,
	})
	if err != nil {
		return guestenrollment.GuestSessionIssueResult{}, fail(ReasonProtocolInvalid, false, false)
	}
	defer zero(request)
	operationContext, cancel := context.WithTimeout(ctx, identityOperationTimeout)
	defer cancel()
	dial := (&net.Dialer{Timeout: identityOperationTimeout}).DialContext
	if client.Dial != nil {
		dial = client.Dial
	}
	connection, err := dial(operationContext, "unix", client.SocketPath)
	if err != nil {
		return guestenrollment.GuestSessionIssueResult{}, fail(ReasonIdentityUnavailable, true, false)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(identityOperationTimeout))
	if _, err := io.Copy(connection, bytes.NewReader(request)); err != nil {
		return guestenrollment.GuestSessionIssueResult{}, fail(ReasonIdentityUnavailable, true, true)
	}
	if writer, ok := connection.(interface{ CloseWrite() error }); !ok || writer.CloseWrite() != nil {
		return guestenrollment.GuestSessionIssueResult{}, fail(ReasonIdentityUnavailable, true, true)
	}
	reader := bufio.NewReader(io.LimitReader(connection, int64(guestenrollment.MaxNativeSessionLocalMessageBytes)+1))
	line, err := reader.ReadBytes('\n')
	if err != nil || len(line) == 0 || len(line) > guestenrollment.MaxNativeSessionLocalMessageBytes {
		zero(line)
		return guestenrollment.GuestSessionIssueResult{}, fail(ReasonIdentityUnavailable, true, true)
	}
	defer zero(line)
	response, err := guestenrollment.DecodeNativeSessionCredentialResponse(line)
	if err != nil {
		return guestenrollment.GuestSessionIssueResult{}, fail(ReasonProtocolInvalid, false, true)
	}
	if response.Error != nil {
		reason := ReasonIdentityUnavailable
		if response.Error.Reason == "replacement-required" {
			reason = ReasonCredentialExpired
		}
		return guestenrollment.GuestSessionIssueResult{}, fail(reason, response.Error.Temporary, response.Error.Uncertain)
	}
	result := *response.Result
	response.Result.Credential.Opaque = ""
	return result, nil
}
