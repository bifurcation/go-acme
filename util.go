package anvil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"hash"
	"log"
	"math/big"
	"strings"
)

const ENABLE_DEBUG = true

func DEBUG(message interface{}) {
	if ENABLE_DEBUG {
		log.Println(message)
	}
}

// Errors

type NotSupportedError string
type MalformedRequestError string
type UnauthorizedError string
type NotFoundError string
type SyntaxError string
type SignatureValidationError string
type CertificateIssuanceError string

func (e NotSupportedError) Error() string        { return string(e) }
func (e MalformedRequestError) Error() string    { return string(e) }
func (e UnauthorizedError) Error() string        { return string(e) }
func (e NotFoundError) Error() string            { return string(e) }
func (e SyntaxError) Error() string              { return string(e) }
func (e SignatureValidationError) Error() string { return string(e) }
func (e CertificateIssuanceError) Error() string { return string(e) }

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
	rand.Read(b) // NOTE: Ignoring errors
	return b64enc(b)
}

func newToken() string {
	return randomString(32)
}

// The missing CertificateRequest.Verify() method

func VerifyCSR(csr *x509.CertificateRequest) error {
	// Compute the hash of the TBSCertificateRequest
	var hashID crypto.Hash
	var hash hash.Hash
	switch csr.SignatureAlgorithm {
	case x509.SHA1WithRSA:
		hashID = crypto.SHA1
		hash = sha1.New()
	case x509.SHA256WithRSA:
		fallthrough
	case x509.ECDSAWithSHA256:
		hashID = crypto.SHA256
		hash = sha256.New()
	case x509.SHA384WithRSA:
		fallthrough
	case x509.ECDSAWithSHA384:
		hashID = crypto.SHA384
		hash = sha512.New384()
	case x509.SHA512WithRSA:
		fallthrough
	case x509.ECDSAWithSHA512:
		hashID = crypto.SHA512
		hash = sha512.New()
	default:
		return errors.New("Unsupported CSR signing algorithm")
	}
	hash.Write(csr.RawTBSCertificateRequest)
	inputHash := hash.Sum(nil)

	// Verify the signature using the public key in the CSR
	switch csr.SignatureAlgorithm {
	case x509.SHA1WithRSA:
		fallthrough
	case x509.SHA256WithRSA:
		fallthrough
	case x509.SHA384WithRSA:
		fallthrough
	case x509.SHA512WithRSA:
		rsaKey := csr.PublicKey.(*rsa.PublicKey)
		return rsa.VerifyPKCS1v15(rsaKey, hashID, inputHash, csr.Signature)
	case x509.ECDSAWithSHA256:
		fallthrough
	case x509.ECDSAWithSHA384:
		fallthrough
	case x509.ECDSAWithSHA512:
		ecKey := csr.PublicKey.(*ecdsa.PublicKey)
		intlen := len(csr.Signature) / 2
		r, s := big.NewInt(0), big.NewInt(0)
		r.SetBytes(csr.Signature[:intlen])
		s.SetBytes(csr.Signature[intlen:])
		if ecdsa.Verify(ecKey, inputHash, r, s) {
			return nil
		} else {
			return errors.New("Invalid ECDSA signature on CSR")
		}
	}

	return errors.New("Unsupported CSR signing algorithm")
}

type LegacyAcmeSignature struct {
	Alg   string     `json:"alg,omitempty"`
	Sig   string     `json:"sig,omitempty"`
	Nonce string     `json:"nonce,omitempty"`
	Jwk   JsonWebKey `json:"jwk,omitempty"`
}

type InvalidSignatureError struct {
	reason string
}

func (e InvalidSignatureError) Error() string {
	return "InvalidSignatureError: " + e.reason
}

func (sig LegacyAcmeSignature) Verify(payload []byte) error {
	if sig.Jwk.KeyType != "RSA" {
		return InvalidSignatureError{"kty == " + sig.Jwk.KeyType + " != RSA"}
	} else if sig.Jwk.Rsa == nil {
		return InvalidSignatureError{"Not RSA"}
	}

	// Compute the signature input
	nonceInput, err := b64dec(sig.Nonce)
	if err != nil {
		return InvalidSignatureError{"b64 decode error on nonce"}
	}
	signatureInput := append(nonceInput, payload...)

	// Import the signature value
	signature, err := b64dec(sig.Sig)
	if err != nil {
		return InvalidSignatureError{"b64 decode error on signature"}
	}

	// Compute the message digest
	// Hash the payload
	var hashID crypto.Hash
	var hash hash.Hash
	switch sig.Alg {
	case "RS256":
		hashID = crypto.SHA256
		hash = sha256.New()
	case "RS384":
		hashID = crypto.SHA384
		hash = sha512.New384()
	case "RS512":
		hashID = crypto.SHA512
		hash = sha512.New()
	default:
		return InvalidSignatureError{"unknown algorithm " + sig.Alg}
	}
	hash.Write(signatureInput)
	inputHash := hash.Sum(nil)

	// Check the signature
	return rsa.VerifyPKCS1v15(sig.Jwk.Rsa, hashID, inputHash, signature)
}
