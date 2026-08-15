package dockerbackend

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
)

const maxDockerOutputBytes = 256 << 10

type dockerCLI struct {
	host string
}

func (cli dockerCLI) Run(ctx context.Context, input io.Reader, arguments ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, "docker", arguments...)
	command.Stdin = input
	command.Env = []string{"DOCKER_HOST=" + cli.host, "HOME=/tmp", "PATH=" + os.Getenv("PATH")}
	var output limitedBuffer
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Run(); err != nil {
		return nil, errors.New("docker operation failed")
	}
	if output.overflow {
		return nil, errors.New("docker output exceeded its bound")
	}
	return output.Bytes(), nil
}

type limitedBuffer struct {
	bytes.Buffer
	overflow bool
}

func (buffer *limitedBuffer) Write(value []byte) (int, error) {
	original := len(value)
	remaining := maxDockerOutputBytes - buffer.Len()
	if remaining <= 0 {
		buffer.overflow = true
		return original, nil
	}
	if len(value) > remaining {
		value = value[:remaining]
		buffer.overflow = true
	}
	_, _ = buffer.Buffer.Write(value)
	return original, nil
}
