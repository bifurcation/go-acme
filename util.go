package acme

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
)

// Errors

type NotFoundError string
type SyntaxError string
type SignatureValidationError string

func (e NotFoundError) Error() string            { return string(e) }
func (e SyntaxError) Error() string              { return string(e) }
func (e SignatureValidationError) Error() string { return string(e) }

// Base64 functions

func pad(x string) string {
	switch len(x) % 4 {
	case 2:
		return x + "=="
	case 3:
		return x + "="
	}
	return x
}

func unpad(x string) string {
	return strings.Replace(x, "=", "", -1)
}

func b64enc(x []byte) string {
	return unpad(base64.URLEncoding.EncodeToString(x))
}

func b64dec(x string) ([]byte, error) {
	return base64.URLEncoding.DecodeString(pad(x))
}

// Random stuff

func randomString(length int) string {
	b := make([]byte, length)
	rand.Read(b) // XXX Ignoring errors as unlikely
	return b64enc(b)
}
