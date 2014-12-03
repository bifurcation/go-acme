package acme

import (
	"crypto/x509"
	"net/http"
)

type AcmeMessage struct {
	// XXX For simplicity, we just put all the fields in here.
	//     This could be a problem if we have fields with the same name
	//     and different types.  If that happens, we'll need to split out
	//     types and do a bunch of reserialization.
	Type         string              `json:"type"`                   // Base
	Error        string              `json:"error,omitempty"`        // error
	Message      string              `json:"message,omitempty"`      //
	MoreInfo     string              `json:"moreInfo,omitempty"`     //
	Token        string              `json:"token,omitempty"`        // defer
	Interval     float64             `json:"interval,omitempty"`     //
	Identifier   string              `json:"identifier,omitempty"`   // challengeRequest
	SessionID    string              `json:"sessionID,omitempty"`    // challenge
	Nonce        string              `json:"nonce,omitempty"`        //
	Challenges   []AcmeChallenge     `json:"challenges,omitempty"`   //
	Combinations [][]int             `json:"combinations,omitempty"` //
	Signature    LegacyAcmeSignature `json:"signature,omitempty"`    // authorizationRequest
	Responses    []AcmeResponse      `json:"responses,omitempty"`    //
	Contact      []string            `json:"contact,omitempty"`      //
	RecoverToken string              `json:"recoverToken,omitempty"` // authorization
	Jwk          JsonWebKey          `json:"jwk,omitempty"`          //
	Csr          string              `json:"csr,omitempty"`          // certificateRequest
	Certificate  string              `json:"certificate,omitempty"`  // certificate
	Chain        []string            `json:"chain,omitempty"`        //
	Refresh      string              `json:"refresh,omitempty"`      //
	// No new fields for statusRequest, revocationRequest, revocation
}

type WebFrontEnd interface {
	ServeHTTP(http.ResponseWriter, *http.Request)

	// Internal messages
	OnAuthorizationUpdate(Authorization)
}

type RegistrationAuthority interface {
	// Web events
	// * POST to new-auth URI
	// * POST to new-cert URI
	// * POST to auth URI ~> not in -00
	// * POST to cert URI == revokeCertificate
	NewAuthorization(AuthorizationRequest, JsonWebKey) (Authorization, error)
	NewCertificate(CertificateRequest, JsonWebKey) (Certificate, error)
	//UpdateAuthorization(Token, UpdateRequest, JsonWebKey) error
	//UpdateCertificate(Token, UpdateRequest, JsonWebKey) error

	// Internal messages
	OnValidationUpdate(Validation)
}

type ValidationAuthority interface {
	// POST to validation URI
	UpdateValidation(Validation) error
}

type CertificateAuthority interface {
	CACertificate() []byte
	IssueCertificate(x509.CertificateRequest) ([]byte, error)
	RevokeCertificate(x509.Certificate) error
}

type StorageReader interface {
	Get(Token) (interface{}, error)
}

type StorageWriter interface {
	Put(interface{}) (Token, error)
	Update(Token, interface{}) error
}

type StorageAuthority interface {
	StorageReader
	StorageWriter
}

// Implemented elsewhere:
// * ${INTERFACE}Impl
// * ${INTERFACE}Delegate
