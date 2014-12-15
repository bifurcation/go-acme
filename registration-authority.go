// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package anvil

import (
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"regexp"
)

type RegistrationAuthorityImpl struct {
	WFE WebFrontEnd
	CA  CertificateAuthority
	SA  StorageAuthority
}

func NewRegistrationAuthorityImpl() RegistrationAuthorityImpl {
	return RegistrationAuthorityImpl{}
}

func forbiddenIdentifier(id string) bool {
	// XXX Flesh this out, and add real policy.  Only rough checks for now

	// If it contains characters not allowed in a domain name ...
	match, err := regexp.MatchString("[^a-zA-Z0-9.-]", id)
	if (err != nil) || match {
		return true
	}

	// If it is entirely numeric (like an IP address) ...
	match, err = regexp.MatchString("[^0-9.]", id)
	if (err != nil) || !match {
		return true
	}

	return false
}

func isEmpty(val string) bool {
	return len(val) == 0
}

func createChallenge(challengeType string) Challenge {
	// Create the challenge
	var challenge Challenge
	switch challengeType {
	case "simpleHttps":
		challenge = SimpleHTTPSChallenge()
	case "dvsni":
		challenge = DvsniChallenge()
	}

	challenge.Status = StatusPending
	return challenge
}

func fingerprint256(data []byte) string {
	d := sha256.New()
	d.Write(data)
	return b64enc(d.Sum(nil))
}

func (ra *RegistrationAuthorityImpl) NewAuthorization(request Authorization, key JsonWebKey) (Authorization, error) {
	zero := Authorization{}
	identifier := request.Identifier

	// Check that the identifier is present and appropriate
	if isEmpty(identifier.Value) {
		return zero, MalformedRequestError("No identifier in authorization request")
	} else if identifier.Type != IdentifierDNS {
		return zero, NotSupportedError("Only domain validation is supported")
	} else if forbiddenIdentifier(identifier.Value) {
		return zero, UnauthorizedError("We will not authorize use of this identifier")
	}

	// Create validations
	authID := Token(newToken())
	simpleHttps := createChallenge(ChallengeTypeSimpleHTTPS)
	dvsni := createChallenge(ChallengeTypeDVSNI)

	// Create a new authorization object
	authz := Authorization{
		ID:         authID,
		Identifier: identifier,
		Key:        key,
		Status:     StatusPending,
		Challenges: map[string]Challenge{
			ChallengeTypeSimpleHTTPS: simpleHttps,
			ChallengeTypeDVSNI:       dvsni,
		},
	}

	// Store the authorization object, then return it
	err := ra.SA.Update(authz.ID, authz)
	if err != nil {
		return authz, err
	}

	return authz, nil
}

func (ra *RegistrationAuthorityImpl) NewCertificate(req CertificateRequest, jwk JsonWebKey) (Certificate, error) {
	csr := req.CSR
	zero := Certificate{}

	// Verify the CSR
	// TODO: Verify that other aspects of the CSR are appropriate
	err := VerifyCSR(csr)
	if err != nil {
		return zero, UnauthorizedError("Invalid signature on CSR")
	}

	// Get the authorized domain list for the authorization key
	obj, err := ra.SA.Get(Token(jwk.Thumbprint))
	if err != nil {
		return zero, UnauthorizedError("No authorized domains for this key")
	}
	domainSet := obj.(map[string]bool)

	// Validate that authorization key is authorized for all domains
	names := csr.DNSNames
	if len(csr.Subject.CommonName) > 0 {
		names = append(names, csr.Subject.CommonName)
	}
	for _, name := range names {
		if !domainSet[name] {
			return zero, UnauthorizedError(fmt.Sprintf("Key not authorized for name %s", name))
		}
	}

	// Create the certificate
	cert, err := ra.CA.IssueCertificate(*csr)
	if err != nil {
		return zero, CertificateIssuanceError("Error issuing certificate")
	}

	// Identify the certificate object by the cert's SHA-256 fingerprint
	certObj := Certificate{
		ID:     Token(fingerprint256(cert)),
		DER:    cert,
		Status: StatusValid,
	}

	ra.SA.Update(certObj.ID, certObj)
	return certObj, nil
}

func (ra *RegistrationAuthorityImpl) RevokeCertificate(cert x509.Certificate) error {
	// Attempt to fetch the corresponding certificate object
	certID := Token(fingerprint256(cert.Raw))
	obj, err := ra.SA.Get(certID)
	if err != nil {
		return err
	}
	certObj := obj.(Certificate)

	// Change the status and update the DB
	certObj.Status = StatusInvalid
	return ra.SA.Update(certID, certObj)
}

func (ra *RegistrationAuthorityImpl) OnValidationUpdate(authz Authorization) {
	// Check to see whether the updated validations are sufficient
	// Current policy is to accept if any validation succeeded
	for _, val := range authz.Challenges {
		if val.Status == StatusValid {
			authz.Status = StatusValid
			break
		}
	}

	// If no validation succeeded, then the authorization is invalid
	// NOTE: This only works because we only ever do one validation
	if authz.Status != StatusValid {
		authz.Status = StatusInvalid
	}
	ra.SA.Update(authz.ID, authz)

	// Record a new domain/key binding, if authorized
	if authz.Status == StatusValid {
		var domainSet map[string]bool
		obj, err := ra.SA.Get(Token(authz.Key.Thumbprint))
		if err != nil {
			domainSet = make(map[string]bool)
		} else {
			domainSet = obj.(map[string]bool)
		}
		domainSet[authz.Identifier.Value] = true
		ra.SA.Update(Token(authz.Key.Thumbprint), domainSet)
	}
}
