// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package anvil

import (
	"crypto/x509"
)

type WebFrontEnd interface {
	// Specialized methods for different functions
}

type RegistrationAuthority interface {
	NewAuthorization(Authorization, JsonWebKey) (Authorization, error)
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
