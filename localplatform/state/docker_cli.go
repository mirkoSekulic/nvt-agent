package state

import (
	"context"
	"errors"
	"io"
	"os/exec"
	"strings"
)

const maxDockerOutputBytes = 64 << 10

// DockerCLI invokes the ordinary Docker CLI without a shell. Stdin may carry
// private state; the implementation never copies it into captured output.
type DockerCLI struct {
	Host string
}

func (cli DockerCLI) Run(ctx context.Context, stdin io.Reader, arguments ...string) ([]byte, error) {
	return cli.RunWithOutputLimit(ctx, stdin, maxDockerOutputBytes, arguments...)
}

// RunWithOutputLimit preserves the ordinary bounded Docker boundary while
// allowing callers with a separately validated payload contract to request a
// larger finite transport bound.
func (cli DockerCLI) RunWithOutputLimit(ctx context.Context, stdin io.Reader, maximum int, arguments ...string) ([]byte, error) {
	if maximum < 1 || maximum > maxStateFileBytes {
		return nil, errors.New("invalid Docker output limit")
	}
	if len(cli.Host) > 4096 || strings.ContainsAny(cli.Host, "\x00\r\n") {
		return nil, errors.New("invalid Docker host")
	}
	if cli.Host != "" {
		arguments = append([]string{"--host", cli.Host}, arguments...)
	}
	command := exec.CommandContext(ctx, "docker", arguments...)
	command.Stdin = stdin
	output := &boundedOutput{maximum: maximum}
	command.Stdout = output
	command.Stderr = output
	err := command.Run()
	if output.exceeded {
		return nil, errors.New("Docker command output exceeded limit")
	}
	return output.data, err
}

type boundedOutput struct {
	data     []byte
	maximum  int
	exceeded bool
}

func (output *boundedOutput) Write(value []byte) (int, error) {
	remaining := output.maximum - len(output.data)
	if remaining < len(value) {
		output.exceeded = true
		if remaining > 0 {
			output.data = append(output.data, value[:remaining]...)
		}
		return len(value), nil
	}
	output.data = append(output.data, value...)
	return len(value), nil
}

var _ CommandBoundary = DockerCLI{}
var _ OutputLimitedCommandBoundary = DockerCLI{}
