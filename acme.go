package acme

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
)

const REQUEST_BUFFER_SIZE = 20 * 1024

const ENABLE_DEBUG = true

func DEBUG(message interface{}) {
	if ENABLE_DEBUG {
		log.Println(message)
	}
}

// ACME Message structures

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

// Quick error factories

func acmeError(code, message string) AcmeMessage {
	return AcmeMessage{
		Type:    "error",
		Error:   code,
		Message: message,
	}
}

func malformedRequestError() AcmeMessage {
	return acmeError("malformed", "Malformed ACME request")
}

func notFoundError() AcmeMessage {
	return acmeError("notFound", "Requested token not found")
}

func internalServerError() AcmeMessage {
	return acmeError("internalServer", "Internal server error")
}

func notSupportedError() AcmeMessage {
	return acmeError("notSupported", "Requested func not supported by this server")
}

func forbiddenError() AcmeMessage {
	return acmeError("forbidden", "Requested action would violate the server's policy")
}

func unauthorizedError(message string) AcmeMessage {
	return acmeError("unauthorized", message)
}

// ACME Web API definition

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

type challengeSet struct {
	Domain     string
	Challenges []AcmeChallenge
}

type pendingAuth struct {
	Domain string
	Key    JsonWebKey
}

type AcmeWebAPI struct {
	// XXX These state variables are just as in node-acme.  We will
	//     want to offload them to something persistent

	issuedChallenges  map[string]challengeSet    // Nonce -> { domain, challenge }
	authorizedKeys    map[string]map[string]bool // Domain -> [ KeyThumbprints ]
	recoveryKeys      map[string]string          // Key -> Domain
	certificates      map[int]string             // Serial -> Certificate
	revocationStatus  map[string]bool            // Certificate -> boolean
	pendingValidation map[string]pendingAuth     // Token -> { domain, key }
	deferredResponses map[string]AcmeMessage     // Token  -> Response

	privateKey     interface{}
	certificate    x509.Certificate
	derCertificate []byte
}

func NewAcmeWebAPI() AcmeWebAPI {
	priv, cert, der := newRoot()

	return AcmeWebAPI{
		issuedChallenges:  make(map[string]challengeSet),
		authorizedKeys:    make(map[string]map[string]bool),
		recoveryKeys:      make(map[string]string),
		certificates:      make(map[int]string),
		revocationStatus:  make(map[string]bool),
		pendingValidation: make(map[string]pendingAuth),
		deferredResponses: make(map[string]AcmeMessage),

		privateKey:     priv,
		certificate:    cert,
		derCertificate: der,
	}
}

func (acme *AcmeWebAPI) finalizePendingAuthorization(pending pendingAuth) {
	curr, ok := acme.authorizedKeys[pending.Domain]
	if !ok || (curr == nil) {
		acme.authorizedKeys[pending.Domain] = make(map[string]bool)
	}
	acme.authorizedKeys[pending.Domain][pending.Key.Thumbprint] = true
}

func (acme *AcmeWebAPI) ProvideDeferredResponse(token string, message AcmeMessage) {
	acme.deferredResponses[token] = message

	pending, ok := acme.pendingValidation[token]
	if ok && message.Type == "authorization" {
		acme.finalizePendingAuthorization(pending)
	}
}

func (acme *AcmeWebAPI) handleChallengeRequest(message AcmeMessage) AcmeMessage {
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
	acme.issuedChallenges[nonce] = challengeSet{
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

func (acme *AcmeWebAPI) handleAuthorizationRequest(message AcmeMessage) AcmeMessage {
	// Retrieve state
	clientNonce := message.Nonce
	challenges, ok := acme.issuedChallenges[clientNonce]
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
	deferralToken := newToken()
	deferralMessage := AcmeMessage{
		Type:  "defer",
		Token: deferralToken,
	}
	go ValidateChallenges(acme, deferralToken, identifier, challenges.Challenges, message.Responses)
	acme.pendingValidation[deferralToken] = pendingAuth{
		Domain: identifier,
		Key:    message.Signature.Jwk,
	}
	acme.ProvideDeferredResponse(deferralToken, deferralMessage)

	return deferralMessage
}

func (acme *AcmeWebAPI) handleCertificateRequest(message AcmeMessage) AcmeMessage {
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
		_, ok := acme.authorizedKeys[name][thumbprint]
		if !ok {
			return unauthorizedError(fmt.Sprintf("Key not authorized for name %s", name))
		}
	}

	// Create the certificate
	cert, err := newEECertificate(csr.PublicKey, names, acme.certificate, acme.privateKey)
	if err != nil {
		return internalServerError()
	}

	return AcmeMessage{
		Type:        "certificate",
		Certificate: b64enc(cert),
		Chain:       []string{b64enc(acme.derCertificate)},
	}
}

func (acme *AcmeWebAPI) handleRevocationRequest(message AcmeMessage) AcmeMessage {
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
		_, ok := acme.authorizedKeys[name][thumbprint]
		if !ok {
			return unauthorizedError(fmt.Sprintf("Key not authorized for name %s", name))
		}
	}

	acme.revocationStatus[message.Certificate] = true
	return AcmeMessage{
		Type: "revocation",
	}
}

func (acme *AcmeWebAPI) handleStatusRequest(message AcmeMessage) AcmeMessage {
	response, ok := acme.deferredResponses[message.Token]
	if !ok {
		return notFoundError()
	}

	if response.Type != "defer" {
		delete(acme.deferredResponses, message.Token)
	}

	return response
}

func (acme *AcmeWebAPI) handleAcmeMessage(message AcmeMessage) AcmeMessage {
	switch message.Type {
	case "challengeRequest":
		return acme.handleChallengeRequest(message)
	case "authorizationRequest":
		return acme.handleAuthorizationRequest(message)
	case "certificateRequest":
		return acme.handleCertificateRequest(message)
	case "revocationRequest":
		return acme.handleRevocationRequest(message)
	case "statusRequest":
		return acme.handleStatusRequest(message)
	default:
		return AcmeMessage{
			Type:    "error",
			Error:   "notSupported",
			Message: "Message type " + message.Type + "not supported"}
	}
}

func (acme AcmeWebAPI) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	// Check that the method is POST
	if request.Method != "POST" {
		DEBUG("Failing due to inability to bad method")
		response.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// XXX Any other checks on request?
	// XXX Check that Content-Type is JSON?  Just duck typing now.

	// Read message body
	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		DEBUG("Failing due to inability to read body")
		DEBUG(err)
		response.WriteHeader(http.StatusBadRequest)
		return
	}

	// Parse JSON
	// TODO Unmarshal into real structures?
	var message AcmeMessage
	err = json.Unmarshal(body, &message)
	if err != nil {
		DEBUG("Failing due to inability to parse JSON")
		response.WriteHeader(http.StatusBadRequest)
		return
	}

	// Perform the actual ACME logic
	reply := acme.handleAcmeMessage(message)

	// Stringify and send the reply
	jsonReply, err := json.Marshal(reply)
	if err != nil {
		DEBUG("Failing due to inability to serialize JSON")
		response.WriteHeader(http.StatusInternalServerError)
		return
	}
	response.WriteHeader(http.StatusOK)
	response.Write(jsonReply)
}
