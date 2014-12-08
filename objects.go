package anvil

import (
	"crypto/x509"
	"net/url"
	"time"
)

type IdentifierType string
type AcmeStatus string
type Date string
type Token string
type Buffer []byte

const (
	StatusPending    = "pending"    // Client has next action
	StatusProcessing = "processing" // Server has next action
	StatusValid      = "valid"
	StatusInvalid    = "invalid"
)

type AcmeIdentifier struct {
	Type  IdentifierType
	Value string
}

type AcmeChallenge struct {
	Type  string `json:"type"`
	Token string `json:"token"` // SimpleHTTPS
	R     string `json:"r"`     // DVSNI
	Nonce string `json:"nonce"`
}

type AcmeResponse struct {
	Type  string `json:"type"`
	Token string `json:"token"` // SimpleHTTPS
	Path  string `json:"path"`  //
	S     string `json:"s"`     // DVSNI
}

type AuthorizationRequest struct {
	Identifier AcmeIdentifier
}

type CertificateRequest struct {
	CSR x509.CertificateRequest
}

// What should go in these
type UpdateRequest struct{}

type Validation struct {
	ID         Token
	Identifier AcmeIdentifier
	Status     AcmeStatus
	Type       string
	Challenge  AcmeChallenge
	Response   AcmeResponse
	URI        url.URL
}

type Authorization struct {
	ID           Token
	Identifier   AcmeIdentifier
	Key          JsonWebKey
	Status       AcmeStatus
	Expires      time.Time
	Validations  []Validation
	Combinations [][]int
}

type Certificate struct {
	ID       Token
	DER      Buffer
	PEM      string
	Chain    []Certificate
	Download url.URL
	Status   AcmeStatus
}
