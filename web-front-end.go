package acme

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

type WebFrontEndImpl struct {
	RA                RegistrationAuthority
	VA                ValidationAuthority
	SA                StorageAuthority
	deferredResponses map[string]AcmeMessage
}

func NewWebFrontEndImpl() WebFrontEndImpl {
	return WebFrontEndImpl{
		deferredResponses: make(map[string]AcmeMessage),
	}
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

// Method implementations

func (wfe WebFrontEndImpl) ServeHTTP(response http.ResponseWriter, request *http.Request) {
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
	var message AcmeMessage
	err = json.Unmarshal(body, &message)
	if err != nil {
		DEBUG("Failing due to inability to parse JSON")
		response.WriteHeader(http.StatusBadRequest)
		return
	}

	// Dispatch by ACME messge type
	var reply AcmeMessage
	switch message.Type {
	case "challengeRequest":
		authz, err := wfe.RA.NewAuthorization(AuthorizationRequest{
			Identifier: AcmeIdentifier{
				Type:  "domain",
				Value: message.Identifier,
			},
		}, JsonWebKey{})

		if err != nil {
			fmt.Printf("error from NewAuthorization(): %+v\n", err)
			reply = internalServerError()
		}

		challenges := make([]AcmeChallenge, len(authz.Validations))
		for i, val := range authz.Validations {
			challenges[i] = val.Challenge
		}

		reply = AcmeMessage{
			Type:       "challenge",
			Nonce:      string(authz.ID),
			Challenges: challenges,
		}
	case "authorizationRequest":
		clientNonce := message.Nonce
		obj, err := wfe.SA.Get(Token(clientNonce))
		if err != nil {
			reply = notFoundError()
			break
		}
		authz := obj.(Authorization)
		identifier := authz.Identifier.Value

		// Validate signature
		clientNonceInput, err := b64dec(clientNonce)
		if err != nil {
			reply = malformedRequestError()
			break
		}
		err = message.Signature.Verify(append([]byte(identifier), clientNonceInput...))
		if err != nil {
			reply = unauthorizedError("Signature failed to validate")
			break
		}

		// Update authorization with JWK and responses
		authz.Key = message.Signature.Jwk
		if len(message.Responses) != len(authz.Validations) {
			reply = malformedRequestError()
			break
		}
		chosen := false
		var chosenValidation Validation
		for i, response := range message.Responses {
			authz.Validations[i].Response = response

			if !chosen && len(response.Type) > 0 {
				chosen = true
				chosenValidation = authz.Validations[i]
			}
		}
		if !chosen {
			reply = malformedRequestError()
			break
		}
		err = wfe.SA.Update(authz.ID, authz)
		// XXX ignoring error

		// Kick off validation
		err = wfe.VA.UpdateValidation(chosenValidation)
		reply = AcmeMessage{
			Type:  "defer",
			Token: string(authz.ID),
		}
	case "certificateRequest":
		// Verify the signature
		csrBytes, err := b64dec(message.Csr)
		if err != nil {
			reply = malformedRequestError()
			break
		}
		err = message.Signature.Verify(csrBytes)
		if err != nil {
			reply = unauthorizedError("Signature failed to validate")
			break
		}

		// Parse the CSR
		if len(message.Csr) == 0 {
			reply = malformedRequestError()
			break
		}
		csr, err := x509.ParseCertificateRequest(csrBytes)
		if err != nil {
			reply = malformedRequestError()
			break
		}

		cert, err := wfe.RA.NewCertificate(CertificateRequest{CSR: *csr}, message.Signature.Jwk)
		if err != nil {
			reply = internalServerError()
			break
		}

		reply = AcmeMessage{
			Type:        "certificate",
			Certificate: b64enc(cert.DER),
		}
	case "revocationRequest":
		// TODO Implement revocation
		reply = notSupportedError()
	case "statusRequest":
		reply, ok := wfe.deferredResponses[message.Token]
		if !ok {
			reply = notFoundError()
			break
		}

		if reply.Type != "defer" {
			delete(wfe.deferredResponses, message.Token)
		}
	default:
		reply = AcmeMessage{
			Type:    "error",
			Error:   "notSupported",
			Message: "Message type " + message.Type + "not supported",
		}
	}

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

func (wfe WebFrontEndImpl) OnAuthorizationUpdate(authz Authorization) {
	token := string(authz.ID)
	_, ok := wfe.deferredResponses[token]
	if !ok || authz.Status == StatusPending {
		return
	}

	switch authz.Status {
	case StatusValid:
		wfe.deferredResponses[token] = AcmeMessage{
			Type:       "authorization",
			Identifier: authz.Identifier.Value,
		}

	case StatusInvalid:
		wfe.deferredResponses[token] = unauthorizedError("Domain authorization failed")
	}
}
