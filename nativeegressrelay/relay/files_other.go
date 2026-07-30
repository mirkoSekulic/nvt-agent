//go:build !linux && !darwin && !freebsd

package relay

import "errors"

func readProcessOwnedFile(string, int, bool) ([]byte, error) {
	return nil, errors.New("native egress relay files require a supported Unix platform")
}
