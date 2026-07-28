//go:build !linux

package nativesession

import (
	"errors"
	"os"
)

func readRootFile(_ string, _ int) ([]byte, error) {
	return nil, errors.New("native session files require Linux")
}

func ownedByRoot(os.FileInfo) bool { return false }
