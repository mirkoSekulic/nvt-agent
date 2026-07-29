//go:build !linux

package nativeegress

import (
	"errors"
	"os"
)

func readProcessOwnedFile(_ string, _ int) ([]byte, error) {
	return nil, errors.New("native egress files require Linux")
}

func ownedByProcess(os.FileInfo) bool { return false }
