//go:build !linux

package nativesession

import (
	"errors"
	"os"
)

func readProcessOwnedFile(_ string, _ int) ([]byte, error) {
	return nil, errors.New("native session files require Linux")
}

func ownedByProcess(os.FileInfo) bool { return false }
