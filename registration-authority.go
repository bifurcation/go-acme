package acme

import (
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
	CA  CertificateAuthority
	SA  StorageAuthority

	valToAuth      map[Token]Token            // ValID -> AuthID
	authorizedKeys map[string]map[string]bool // Domain -> [ KeyThumbprints ]
}

func NewRegistrationAuthorityImpl() RegistrationAuthorityImpl {
	return RegistrationAuthorityImpl{
		valToAuth:      make(map[Token]Token),
		authorizedKeys: make(map[string]map[string]bool),
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

func createValidation(challengeType string) Validation {
	// Create the challenge
	var challenge AcmeChallenge
	switch challengeType {
	case "simpleHttps":
		challenge = SimpleHTTPSChallenge()
	case "dvsni":
		challenge = DvsniChallenge()
	}

	return Validation{
		ID:        Token(newToken()),
		Status:    StatusPending,
		Type:      challengeType,
		Challenge: challenge,
	}
}

func (ra *RegistrationAuthorityImpl) NewAuthorization(request AuthorizationRequest, key JsonWebKey) (Authorization, error) {
	zero := Authorization{}
	identifier := request.Identifier

	// Check that the identifier is present and appropriate
	if isEmpty(identifier.Value) {
		return zero, MalformedRequestError("No identifier in authorization request")
	} else if identifier.Type != "domain" {
		return zero, NotSupportedError("Only domain validation is supported")
	} else if forbiddenIdentifier(identifier.Value) {
		return zero, UnauthorizedError("We will not authorize use of this identifier")
	}

	// Create and store validations
	authID := Token(newToken())
	simpleHttps := createValidation("simpleHttps")
	simpleHttps.AuthID = authID
	simpleHttps.Identifier = identifier
	dvsni := createValidation("dvsni")
	dvsni.AuthID = authID
	dvsni.Identifier = identifier
	ra.valToAuth[simpleHttps.ID] = authID
	ra.valToAuth[dvsni.ID] = authID

	// Create a new authorization object
	authz := Authorization{
		ID:         authID,
		Identifier: identifier,
		Key:        key,
		Status:     StatusPending,
		Validations: []Validation{
			simpleHttps,
			dvsni,
		},
	}

	// Store the authorization object, then return it
	ra.SA.Update(authz.ID, authz)
	return authz, nil
}

func (ra *RegistrationAuthorityImpl) NewCertificate(req CertificateRequest, jwk JsonWebKey) (Certificate, error) {
	csr := req.CSR
	zero := Certificate{}

	// Verify the CSR
	// TODO: Verify that other aspects of the CSR are appropriate
	err := VerifyCSR(&csr)
	if err != nil {
		return zero, UnauthorizedError("Invalid signature on CSR")
	}

	// Validate that authorization key is authorized for all domains
	names := csr.DNSNames
	if len(csr.Subject.CommonName) > 0 {
		names = append(names, csr.Subject.CommonName)
	}
	thumbprint := jwk.Thumbprint
	for _, name := range names {
		ok := ra.authorizedKeys[name][thumbprint]
		if !ok {
			return zero, UnauthorizedError(fmt.Sprintf("Key not authorized for name %s", name))
		}
	}

	// Create the certificate
	cert, err := ra.CA.IssueCertificate(csr)
	// XXX: Ignoring error

	return Certificate{
		ID:  Token(newToken()),
		DER: cert,
	}, nil
}

func (ra *RegistrationAuthorityImpl) OnValidationUpdate(val Validation) {
	// If the validation didn't succeed, there's no point
	if val.Status != StatusValid {
		return
	}

	// Retrieve the relevant authorization
	authID, ok := ra.valToAuth[val.ID]
	if !ok {
		return
	}
	obj, err := ra.SA.Get(authID)
	if err != nil {
		return
	}
	authz := obj.(Authorization)

	// Update the authorization and cache locally
	for i, curr := range authz.Validations {
		if val.ID == curr.ID {
			authz.Validations[i] = val
			break
		}
	}
	_, ok = ra.authorizedKeys[authz.Identifier.Value][authz.Key.Thumbprint]
	if !ok {
		ra.authorizedKeys[authz.Identifier.Value] = make(map[string]bool)
	}

	ra.authorizedKeys[authz.Identifier.Value][authz.Key.Thumbprint] = true
	ra.SA.Update(authz.ID, authz)

	ra.WFE.OnAuthorizationUpdate(authz)
}
