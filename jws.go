package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"hash"
	"math/big"
	// jwk.go
	// util.go
)

// JWS

type JwsHeader struct {
	Algorithm string     `json:"alg,omitempty"`
	Nonce     string     `json:"nonce,omitempty"`
	Key       JsonWebKey `json:"jwk,omitempty"`
}

type JwsProtectedHeader struct {
	Algorithm string `json:"alg,omitempty"`
	Nonce     string `json:"nonce,omitempty"`
}

// rawJsonWebSignature and JsonWebSignature are the same.
// We just use rawJsonWebSignature for the basic parse,
// and JsonWebSignature for the full parse
type rawJsonWebSignature struct {
	Header    JwsHeader `json:"header,omitempty"`
	Protected string    `json:"protected,omitempty"`
	Payload   string    `json:"payload,omitempty"`
	Signature string    `json:"signature,omitempty"`
}

type JsonWebSignature rawJsonWebSignature

// No need for special MarshalJSON handling; it's OK for
// elements to remain in the unprotected header, since they'll
// just be overwritten.
// func (jwk JsonWebKey) MarshalJSON() ([]byte, error) {}

// On unmarshal, copy protected header fields to protected
func (jwk *JsonWebSignature) UnmarshalJSON(data []byte) error {
	var raw rawJsonWebSignature
	err := json.Unmarshal(data, &raw)
	if err != nil {
		return err
	}

	// Copy over simple fields
	jwk.Header = raw.Header
	jwk.Protected = raw.Protected
	jwk.Payload = raw.Payload
	jwk.Signature = raw.Signature

	if len(jwk.Protected) > 0 {
		protectedJSON, err := b64dec(jwk.Protected)
		if err != nil {
			return err
		}

		// This should overwrite fields in jwk.Header if there is a conflict
		err = json.Unmarshal(protectedJSON, &jwk.Header)
		if err != nil {
			return err
		}
	}

	return nil
}

func (jwk *JsonWebSignature) Verify() error {
	// Decode the payload and signature
	sig, err := b64dec(jwk.Signature)
	if err != nil {
		return err
	}

	// Compute the signature input
	input := []byte(jwk.Protected + "." + jwk.Payload)

	// Parse the "alg" value
	// For example:
	//  "RS256" => "R"=PKCS1v15 + "256"=sha256
	if len(jwk.Header.Algorithm) != 5 {
		return SyntaxError("Invalid Algorithm")
	}
	sigAlg, hashAlg := jwk.Header.Algorithm[:1], jwk.Header.Algorithm[2:]

	// Hash the payload
	var hashID crypto.Hash
	var hash hash.Hash
	switch hashAlg {
	case "256":
		hashID = crypto.SHA256
		hash = sha256.New()
	case "384":
		hashID = crypto.SHA384
		hash = sha512.New384()
	case "512":
		hashID = crypto.SHA512
		hash = sha512.New()
	default:
		return SyntaxError("Invalid hash length " + hashAlg)
	}
	hash.Write(input)
	inputHash := hash.Sum(nil)

	// Check the signature
	switch sigAlg {
	case "R":
		return rsa.VerifyPKCS1v15(jwk.Header.Key.Rsa, hashID, inputHash, sig)
	case "P":
		return rsa.VerifyPSS(jwk.Header.Key.Rsa, hashID, inputHash, sig, nil)
	case "E":
		intlen := len(sig) / 2
		rBytes, sBytes := sig[:intlen], sig[intlen:]
		r, s := big.NewInt(0), big.NewInt(0)
		r.SetBytes(rBytes)
		s.SetBytes(sBytes)
		if ecdsa.Verify(jwk.Header.Key.Ec, inputHash, r, s) {
			return nil
		} else {
			return SignatureValidationError("ECDSA signature validation failed")
		}
	default:
		return SyntaxError("Invalid signature algorithm " + hashAlg)
	}
}
