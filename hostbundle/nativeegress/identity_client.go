package nativeegress

import (
	"bufio"
	"bytes"
	"context"
	"errors"
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

func (client *IdentityClient) Issue(ctx context.Context) (guestenrollment.NativeEgressIssueResult, error) {
	if client == nil || ctx == nil || !validFile(client.SocketPath) {
		return guestenrollment.NativeEgressIssueResult{}, fail(ReasonConfiguration, false, false)
	}
	request, err := guestenrollment.EncodeNativeEgressCredentialRequest(guestenrollment.NativeEgressCredentialRequest{
		ContractVersion: guestenrollment.NativeEgressLocalVersion,
		Type:            guestenrollment.NativeEgressCredentialIssue,
	})
	if err != nil {
		return guestenrollment.NativeEgressIssueResult{}, fail(ReasonProtocolInvalid, false, false)
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
		return guestenrollment.NativeEgressIssueResult{}, fail(ReasonIdentityUnavailable, true, false)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(identityOperationTimeout))
	if _, err := io.Copy(connection, bytes.NewReader(request)); err != nil {
		return guestenrollment.NativeEgressIssueResult{}, fail(ReasonIdentityUnavailable, true, true)
	}
	if writer, ok := connection.(interface{ CloseWrite() error }); !ok || writer.CloseWrite() != nil {
		return guestenrollment.NativeEgressIssueResult{}, fail(ReasonIdentityUnavailable, true, true)
	}
	reader := bufio.NewReader(io.LimitReader(connection, int64(guestenrollment.MaxNativeEgressLocalMessageBytes)+1))
	line, err := reader.ReadBytes('\n')
	if err != nil || len(line) == 0 || len(line) > guestenrollment.MaxNativeEgressLocalMessageBytes {
		zero(line)
		return guestenrollment.NativeEgressIssueResult{}, fail(ReasonIdentityUnavailable, true, true)
	}
	defer zero(line)
	response, err := guestenrollment.DecodeNativeEgressCredentialResponse(line)
	if err != nil {
		return guestenrollment.NativeEgressIssueResult{}, fail(ReasonProtocolInvalid, false, true)
	}
	if _, trailingErr := reader.ReadByte(); !errors.Is(trailingErr, io.EOF) {
		if response.Result != nil {
			response.Result.Credential.Opaque = ""
		}
		return guestenrollment.NativeEgressIssueResult{}, fail(ReasonProtocolInvalid, false, true)
	}
	if response.Error != nil {
		reason := ReasonIdentityUnavailable
		if response.Error.Reason == "replacement-required" {
			reason = ReasonCredentialExpired
		}
		return guestenrollment.NativeEgressIssueResult{}, fail(reason, response.Error.Temporary, response.Error.Uncertain)
	}
	result := *response.Result
	response.Result.Credential.Opaque = ""
	return result, nil
}
