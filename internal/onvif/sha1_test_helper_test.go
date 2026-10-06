package onvif

import (
	"crypto/sha1" //nolint:gosec // test vector helper mirroring ONVIF digest
)

// sha1Wrapper wraps sha1 for tests.
func sha1Wrapper(s string) []byte {
	h := sha1.Sum([]byte(s))
	return h[:]
}
