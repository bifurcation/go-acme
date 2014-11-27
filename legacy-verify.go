package acme

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
)

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
