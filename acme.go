package acme

import (
	"crypto/x509"
	"encoding/json"
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
	Type         string           `json:"type"`                   // Base
	Error        string           `json:"error,omitempty"`        // error
	Message      string           `json:"message,omitempty"`      //
	MoreInfo     string           `json:"moreInfo,omitempty"`     //
	Token        string           `json:"token,omitempty"`        // defer
	Interval     float64          `json:"interval,omitempty"`     //
	Identifier   string           `json:"identifier,omitempty"`   // challengeRequest
	SessionID    string           `json:"sessionID,omitempty"`    // challenge
	Nonce        string           `json:"nonce,omitempty"`        //
	Challenges   []AcmeChallenge  `json:"challenges,omitempty"`   //
	Combinations [][]int          `json:"combinations,omitempty"` //
	Signature    JsonWebSignature `json:"signature,omitempty"`    // authorizationRequest
	Responses    []AcmeResponse   `json:"responses,omitempty"`    //
	Contact      []string         `json:"contact,omitempty"`      //
	RecoverToken string           `json:"recoverToken,omitempty"` // authorization
	Jwk          JsonWebKey       `json:"jwk,omitempty"`          //
	Csr          string           `json:"csr,omitempty"`          // certificateRequest
	Certificate  string           `json:"certificate,omitempty"`  // certificate
	Chain        []string         `json:"chain,omitempty"`        //
	Refresh      string           `json:"refresh,omitempty"`      //
	// No new fields for statusRequest, revocationRequest, revocation
}

type AcmeChallenge struct {
	// XXX Same flat strategy as with AcmeMessage
	// TODO
}

type AcmeResponse struct {
	// XXX Same flat strategy as with AcmeMessage
	// TODO
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

type AcmeWebAPI struct {
	// XXX These state variables are just as in node-acme.  We will
	//     want to offload them to something persistent

	issuedChallenges  map[string]challengeSet // Nonce -> { domain, challenge }
	authorizedKeys    map[string][]string     // Domain -> [ KeyThumbprints ]
	recoveryKeys      map[string]string       // Key -> Domain
	certificates      map[int]string          // Serial -> Certificate
	revocationStatus  map[string]bool         // Certificate -> boolean
	deferredResponses map[string]AcmeMessage  // Token  -> Response
}

func (acme *AcmeWebAPI) Init() {
	acme.issuedChallenges = make(map[string]challengeSet)
	acme.authorizedKeys = make(map[string][]string)
	acme.recoveryKeys = make(map[string]string)
	acme.certificates = make(map[int]string)
	acme.revocationStatus = make(map[string]bool)
	acme.deferredResponses = make(map[string]AcmeMessage)
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
	challenges := []AcmeChallenge{} // TODO generate
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

	// TODO Verify signature
	// TODO Do validation

	return AcmeMessage{
		Type:       "authorization",
		Identifier: identifier,
	}
}

func (acme *AcmeWebAPI) handleCertificateRequest(message AcmeMessage) AcmeMessage {
	// TODO Verify signature

	// Parse the CSR
	if isEmpty(message.Csr) {
		return malformedRequestError()
	}
	csrBytes, err := b64dec(message.Csr)
	if err != nil {
		return malformedRequestError()
	}
	_, err = x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return malformedRequestError()
	}
	// TODO Verify the CSR
	// TODO Verify that the CSR is authorized by the signature
	// TODO Create the certificate

	return AcmeMessage{
		Type:        "certificate",
		Certificate: randomString(512),
	}
}

func (acme *AcmeWebAPI) handleRevocationRequest(message AcmeMessage) AcmeMessage {
	// TODO Verify signature
	// TODO Check that certificate is one of ours, and associated with the signing key

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
	// Initialize state
	acme.Init()

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
