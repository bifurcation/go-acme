package acme

import (
	"crypto/x509"
	"fmt"
	"regexp"
)

type challengeSet struct {
	Domain     string
	Challenges []AcmeChallenge
}

type pendingAuth struct {
	Domain string
	Key    JsonWebKey
}

type RegistrationAuthorityImpl struct {
	WFE WebFrontEnd
	VA  ValidationAuthority
	CA  CertificateAuthority

	issuedChallenges  map[string]challengeSet    // Nonce -> { domain, challenge }
	authorizedKeys    map[string]map[string]bool // Domain -> [ KeyThumbprints ]
	recoveryKeys      map[string]string          // Key -> Domain
	pendingValidation map[string]pendingAuth     // Token -> { domain, key }
}

func NewRegistrationAuthorityImpl() RegistrationAuthorityImpl {
	return RegistrationAuthorityImpl{
		issuedChallenges:  make(map[string]challengeSet),
		authorizedKeys:    make(map[string]map[string]bool),
		recoveryKeys:      make(map[string]string),
		pendingValidation: make(map[string]pendingAuth),
	}
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

func (ra RegistrationAuthorityImpl) HandleChallengeRequest(message AcmeMessage) AcmeMessage {
	identifier := message.Identifier

	// Check that the identifier is present and appropriate
	if isEmpty(identifier) {
		return malformedRequestError()
	} else if forbiddenIdentifier(identifier) {
		return forbiddenError()
	}

	// Generate a random nonce and challenge
	nonce := randomString(32)
	challenges := []AcmeChallenge{
		SimpleHTTPSChallenge(),
		DvsniChallenge(),
	}
	ra.issuedChallenges[nonce] = challengeSet{
		Domain:     identifier,
		Challenges: challenges,
	}

	// Return nonce, challenge
	return AcmeMessage{
		Type:       "challenge",
		Nonce:      nonce,
		Challenges: challenges,

		// XXX: We don't actually use this; we key off the nonce
		// The session ID is mainly useful in future scenarios where
		// there can be multiple challenge/response round-trips.
		SessionID: randomString(32),
	}
}

func (ra RegistrationAuthorityImpl) HandleAuthorizationRequest(message AcmeMessage) AcmeMessage {
	// Retrieve state
	clientNonce := message.Nonce
	challenges, ok := ra.issuedChallenges[clientNonce]
	if !ok {
		return notFoundError()
	}
	identifier := challenges.Domain

	// Verify signature
	clientNonceInput, err := b64dec(clientNonce)
	if err != nil {
		return malformedRequestError()
	}
	err = message.Signature.Verify(append([]byte(identifier), clientNonceInput...))
	if err != nil {
		return unauthorizedError("Signature failed to validate")
	}

	// Do validation
	deferralToken, err := ra.VA.Validate(identifier, challenges.Challenges, message.Responses)
	if err != nil {
		return malformedRequestError()
	}

	deferralMessage := AcmeMessage{
		Type:  "defer",
		Token: deferralToken,
	}
	ra.pendingValidation[deferralToken] = pendingAuth{
		Domain: identifier,
		Key:    message.Signature.Jwk,
	}
	ra.WFE.ProvideDeferredResponse(deferralToken, deferralMessage)

	return deferralMessage
}

func (ra RegistrationAuthorityImpl) HandleCertificateRequest(message AcmeMessage) AcmeMessage {
	// Verify signature
	csrBytes, err := b64dec(message.Csr)
	if err != nil {
		return malformedRequestError()
	}
	err = message.Signature.Verify(csrBytes)
	if err != nil {
		return unauthorizedError("Signature failed to validate")
	}

	// Parse the CSR
	if isEmpty(message.Csr) {
		return malformedRequestError()
	}
	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return malformedRequestError()
	}

	// Verify the CSR
	// TODO: Verify that other aspects of the CSR are appropriate
	err = VerifyCSR(csr)
	if err != nil {
		return unauthorizedError("Invalid signature on CSR")
	}

	// Validate that authorization key is authorized for all domains
	names := csr.DNSNames
	if len(csr.Subject.CommonName) > 0 {
		names = append(names, csr.Subject.CommonName)
	}
	thumbprint := message.Signature.Jwk.Thumbprint
	for _, name := range names {
		ok := ra.authorizedKeys[name][thumbprint]
		if !ok {
			return unauthorizedError(fmt.Sprintf("Key not authorized for name %s", name))
		}
	}

	// Create the certificate
	cert, err := ra.CA.IssueCertificate(*csr)

	return AcmeMessage{
		Type:        "certificate",
		Certificate: b64enc(cert),
	}
}

func (ra RegistrationAuthorityImpl) HandleRevocationRequest(message AcmeMessage) AcmeMessage {
	// Verify signature
	der, err := b64dec(message.Certificate)
	if err != nil {
		return malformedRequestError()
	}
	err = message.Signature.Verify(der)
	if err != nil {
		return unauthorizedError("Signature failed to validate")
	}

	// Parse the certificate
	if isEmpty(message.Certificate) {
		return malformedRequestError()
	}
	certs, err := x509.ParseCertificates(der)
	if err != nil || len(certs) == 0 {
		return malformedRequestError()
	}
	cert := certs[0]

	// Validate that authorization key is authorized for all domains
	names := cert.DNSNames
	if len(cert.Subject.CommonName) > 0 {
		names = append(names, cert.Subject.CommonName)
	}
	thumbprint := message.Signature.Jwk.Thumbprint
	for _, name := range names {
		_, ok := ra.authorizedKeys[name][thumbprint]
		if !ok {
			return unauthorizedError(fmt.Sprintf("Key not authorized for name %s", name))
		}
	}

	// XXX Pass to CA ra.revocationStatus[message.Certificate] = true
	err = ra.CA.RevokeCertificate(*cert)
	if err != nil {
		return internalServerError()
	}

	return AcmeMessage{
		Type: "revocation",
	}
}

func (ra RegistrationAuthorityImpl) HandleValidationResult(token string, message AcmeMessage) {
	pending, ok := ra.pendingValidation[token]
	if ok && message.Type == "authorization" {
		curr, ok := ra.authorizedKeys[pending.Domain]
		if !ok || (curr == nil) {
			ra.authorizedKeys[pending.Domain] = make(map[string]bool)
		}
		ra.authorizedKeys[pending.Domain][pending.Key.Thumbprint] = true
	}

	ra.WFE.ProvideDeferredResponse(token, message)
}
