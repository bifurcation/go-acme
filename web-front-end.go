package acme

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
)

type WebFrontEndImpl struct {
	RA                RegistrationAuthority
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
		reply = wfe.RA.HandleChallengeRequest(message)
	case "authorizationRequest":
		reply = wfe.RA.HandleAuthorizationRequest(message)
	case "certificateRequest":
		reply = wfe.RA.HandleCertificateRequest(message)
	case "revocationRequest":
		reply = wfe.RA.HandleRevocationRequest(message)
	case "statusRequest":
		reply = wfe.handleStatusRequest(message)
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

func (wfe *WebFrontEndImpl) handleStatusRequest(message AcmeMessage) AcmeMessage {
	response, ok := wfe.deferredResponses[message.Token]
	if !ok {
		return notFoundError()
	}

	if response.Type != "defer" {
		delete(wfe.deferredResponses, message.Token)
	}

	return response
}

func (wfe WebFrontEndImpl) ProvideDeferredResponse(token string, message AcmeMessage) {
	wfe.deferredResponses[token] = message
}
