// Package captureinspect recovers bounded hostname intent from an already
// accepted transparently redirected TCP connection. It is transport-neutral:
// callers retain authority over the exact egress target and final policy.
package captureinspect

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"net"
	"net/http"
	"strings"
)

var ErrHostnameUnavailable = errors.New("hostname unavailable")

// InspectHostname returns the HTTP Host or TLS SNI from the bounded prefix
// without consuming it. Opaque TCP, fragmented ClientHello records, and ECH
// return ErrHostnameUnavailable so callers can retain the original IP intent.
func InspectHostname(reader *bufio.Reader, limit int) (string, error) {
	if reader == nil {
		return "", ErrHostnameUnavailable
	}
	prefix, err := reader.Peek(1)
	if err != nil {
		return "", ErrHostnameUnavailable
	}
	if prefix[0] == 0x16 {
		return inspectTLSSNI(reader, limit)
	}
	return inspectHTTPHost(reader, limit)
}

func inspectHTTPHost(reader *bufio.Reader, limit int) (string, error) {
	const delimiter = "\r\n\r\n"
	if limit <= 0 {
		return "", errors.New("invalid HTTP preface")
	}
	scanned := 0
	for {
		buffered := reader.Buffered()
		if buffered > limit {
			buffered = limit
		}
		if buffered > scanned {
			peek, err := reader.Peek(buffered)
			if err != nil {
				return "", ErrHostnameUnavailable
			}
			start := scanned - (len(delimiter) - 1)
			if start < 0 {
				start = 0
			}
			if relative := bytes.Index(peek[start:], []byte(delimiter)); relative >= 0 {
				end := start + relative
				return parseHTTPHost(peek[:end+len(delimiter)])
			}
			scanned = buffered
			if scanned >= limit {
				return "", errors.New("invalid HTTP preface")
			}
		}

		_, err := reader.Peek(reader.Buffered() + 1)
		if err != nil {
			if reader.Buffered() > scanned {
				continue
			}
			return "", ErrHostnameUnavailable
		}
	}
}

func parseHTTPHost(preface []byte) (string, error) {
	request, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(preface)))
	if err != nil {
		return "", errors.New("malformed HTTP preface")
	}
	host := request.Host
	if split, _, splitErr := net.SplitHostPort(host); splitErr == nil {
		host = split
	}
	if host == "" || strings.ContainsAny(host, "\r\n") {
		return "", ErrHostnameUnavailable
	}
	return strings.ToLower(host), nil
}

func inspectTLSSNI(reader *bufio.Reader, limit int) (string, error) {
	header, err := reader.Peek(5)
	if err != nil {
		return "", ErrHostnameUnavailable
	}
	length := int(binary.BigEndian.Uint16(header[3:5]))
	if length <= 0 || length+5 > limit {
		return "", errors.New("invalid TLS preface")
	}
	record, err := reader.Peek(length + 5)
	if err != nil {
		return "", ErrHostnameUnavailable
	}
	var sni string
	server, client := net.Pipe()
	done := make(chan error, 1)
	go func() {
		tlsServer := tls.Server(server, &tls.Config{
			GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
				sni = hello.ServerName
				return nil, errors.New("inspection complete")
			},
		})
		done <- tlsServer.Handshake()
		_ = server.Close()
	}()
	if _, err := client.Write(record); err != nil {
		_ = client.Close()
		<-done
		return "", ErrHostnameUnavailable
	}
	_ = client.Close()
	<-done
	if sni == "" {
		return "", ErrHostnameUnavailable
	}
	return strings.ToLower(sni), nil
}

func invalidOriginalDestination() error {
	return errors.New("original destination unavailable")
}
