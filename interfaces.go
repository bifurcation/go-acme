package anvil

import (
	"crypto/x509"
	"net/http"
)

type WebFrontEnd interface {
	ServeHTTP(http.ResponseWriter, *http.Request)

	// Internal messages
	OnAuthorizationUpdate(Authorization)
}

type RegistrationAuthority interface {
	NewAuthorization(AuthorizationRequest, JsonWebKey) (Authorization, error)
	NewCertificate(CertificateRequest, JsonWebKey) (Certificate, error)
	RevokeCertificate(x509.Certificate) error

	// Internal messages
	OnValidationUpdate(Authorization)
}

type ValidationAuthority interface {
	UpdateValidations(Authorization) error
}

type CertificateAuthority interface {
	IssueCertificate(x509.CertificateRequest) ([]byte, error)
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
