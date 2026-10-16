//go:build !linux

package harden

import (
	"errors"

	"github.com/cautem/quarshell-core/policy"
)

var errLandlockUnavailable = errors.New("landlock only available on linux")

func landlockABI() (int, error) {
	return 0, errLandlockUnavailable
}

func applyLandlockWithABI(_ policy.Document, _ int) error {
	return errLandlockUnavailable
}
