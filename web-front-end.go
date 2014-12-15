// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package anvil

import (
	"encoding/json"
	"fmt"
	"github.com/bifurcation/gose"
	"io/ioutil"
	"net/http"
	"regexp"
)

type WebFrontEndImpl struct {
	RA RegistrationAuthority
	VA ValidationAuthority
	SA StorageAuthority

	// URL configuration parameters
	baseURL   string
	authzBase string
	certBase  string
}

func NewWebFrontEndImpl() WebFrontEndImpl {
	wfe := WebFrontEndImpl{}

	// TODO: Store HTTP config info, e.g., base URL
	// IDs get appended to these to make URLs for authz
	// objects and certificates
	wfe.baseURL = "http://localhost:4000/acme/" // XXX Set this to where the server will be!!!
	wfe.authzBase = wfe.baseURL + "authz/"
	wfe.certBase = wfe.baseURL + "cert/"

	return wfe
}

// Method implementations

func verifyPOST(request *http.Request) ([]byte, error) {
	zero := []byte{}

	// Read body
	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		fmt.Printf("Error reading body: %+v\n", err)
		return zero, err
	}

	// Parse as JWS
	var jws jose.JsonWebSignature
	err = json.Unmarshal(body, &jws)
	if err != nil {
		fmt.Printf("JWS unmarshal error: %+v\n", err)
		return zero, err
	}

	// Verify JWS
	err = jws.Verify()
	if err != nil {
		fmt.Printf("JWS verify error: %+v\n", err)
		return zero, err
	}

	// TODO Return JWS body
	return []byte(jws.Payload), nil
}

func makePathFromID(id string) string {
	// TODO
	return ""
}

// The ID is always the last slash-separated token in the path
func parseIDFromPath(path string) string {
	re := regexp.MustCompile("^.*/")
	return re.ReplaceAllString(path, "")
}

func (wfe *WebFrontEndImpl) NewAuthz(response http.ResponseWriter, request *http.Request) {
	if request.Method != "POST" {
		http.Error(response, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := verifyPOST(request)
	if err != nil {
		http.Error(response, "Unable to read body", http.StatusBadRequest)
		return
	}

	var init Authorization
	err = json.Unmarshal(body, &init)
	if err != nil {
		http.Error(response, "Error unmarshaling JSON", http.StatusBadRequest)
		return
	}

	// TODO: Create new authz and return
	authz, err := wfe.RA.NewAuthorization(init, JsonWebKey{})
	if err != nil {
		http.Error(response,
			fmt.Sprintf("Error creating new authz: %+v", err),
			http.StatusInternalServerError)
		return
	}

	// Make a URL for this authz, then blow away the ID before serializing
	authzURL := wfe.authzBase + string(authz.ID)
	authz.ID = Token("")
	responseBody, err := json.Marshal(authz)
	if err != nil {
		http.Error(response, "Error marshaling authz", http.StatusInternalServerError)
		return
	}

	response.Header().Add("Location", authzURL)
	response.WriteHeader(http.StatusCreated)
	response.Write(responseBody)
}

func (wfe *WebFrontEndImpl) NewCert(response http.ResponseWriter, request *http.Request) {
	if request.Method != "POST" {
		http.Error(response, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := verifyPOST(request)
	if err != nil {
		http.Error(response, "Unable to read body", http.StatusBadRequest)
		return
	}

	var init CertificateRequest
	err = json.Unmarshal(body, &init)
	if err != nil {
		fmt.Printf("Error unmarshaling certificate request body: %+v\n", err)
		fmt.Printf("Body: %s", string(body))
		http.Error(response, "Error unmarshaling certificate request", http.StatusBadRequest)
		return
	}

	// TODO: Create new certificate and return
	cert, err := wfe.RA.NewCertificate(init, JsonWebKey{})
	if err != nil {
		http.Error(response,
			fmt.Sprintf("Error creating new cert: %+v", err),
			http.StatusBadRequest)
		return
	}

	// Make a URL for this authz
	certURL := wfe.certBase + string(cert.ID)

	// TODO: Content negotiation for cert format
	response.Header().Add("Location", certURL)
	response.WriteHeader(http.StatusCreated)
	response.Write(cert.DER)
}

func (wfe *WebFrontEndImpl) Authz(response http.ResponseWriter, request *http.Request) {
	// Requests to this handler should have a path that leads to a known authz
	id := parseIDFromPath(request.URL.Path)
	obj, err := wfe.SA.Get(Token(id))
	if err != nil {
		http.Error(response,
			fmt.Sprintf("Unable to find authorization: %+v", err),
			http.StatusNotFound)
		return
	}
	authz := obj.(Authorization)

	switch request.Method {
	default:
		http.Error(response, "Method not allowed", http.StatusMethodNotAllowed)
		return

	case "POST":
		body, err := verifyPOST(request)
		if err != nil {
			http.Error(response, "Unable to read body", http.StatusBadRequest)
			return
		}

		var init Authorization
		err = json.Unmarshal(body, &init)
		if err != nil {
			http.Error(response, "Error unmarshaling authorization", http.StatusBadRequest)
			return
		}

		// Copy any new fields from new challenges to old challenges
		// XXX: Should this be done by the RA?
		for t, challenge := range authz.Challenges {
			resp, ok := init.Challenges[t]
			if !ok {
				continue
			}

			authz.Challenges[t] = challenge.MergeResponse(resp)
		}

		wfe.SA.Update(authz.ID, authz)
		wfe.VA.UpdateValidations(authz)

		jsonReply, err := json.Marshal(authz)
		if err != nil {
			http.Error(response, "Failed to marshal authz", http.StatusInternalServerError)
			return
		}
		response.WriteHeader(http.StatusAccepted)
		response.Write(jsonReply)

	case "GET":
		jsonReply, err := json.Marshal(authz)
		if err != nil {
			http.Error(response, "Failed to marshal authz", http.StatusInternalServerError)
			return
		}
		response.WriteHeader(http.StatusOK)
		response.Write(jsonReply)
	}
}

func (wfe *WebFrontEndImpl) Cert(response http.ResponseWriter, request *http.Request) {
	switch request.Method {
	default:
		http.Error(response, "Method not allowed", http.StatusMethodNotAllowed)
		return

	case "GET":
		id := parseIDFromPath(request.URL.Path)
		obj, err := wfe.SA.Get(Token(id))
		if err != nil {
			http.Error(response, "Not found", http.StatusNotFound)
			return
		}
		cert := obj.(Certificate)

		// TODO: Content negotiation
		// TODO: Link header
		jsonReply, err := json.Marshal(cert)
		if err != nil {
			http.Error(response, "Failed to marshal cert", http.StatusInternalServerError)
			return
		}
		response.WriteHeader(http.StatusOK)
		response.Write(jsonReply)

	case "POST":
		// TODO: Handle revocation in POST
	}
}

/*
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
		// Look up the authorization from the client nonce
		clientNonce := message.Nonce
		obj, err := wfe.SA.Get(Token(clientNonce))
		if err != nil {
			reply = notFoundError()
			break
		}
		authz := obj.(Authorization)
		identifier := authz.Identifier.Value

		// Verify signature
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
		for i, response := range message.Responses {
			authz.Validations[i].Response = response
		}
		err = wfe.SA.Update(authz.ID, authz)
		if err != nil {
			reply = internalServerError()
			break
		}

		// Kick off validation
		err = wfe.VA.UpdateValidations(authz)
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
		// Verify the signature
		certBytes, err := b64dec(message.Certificate)
		if err != nil {
			reply = malformedRequestError()
			break
		}
		err = message.Signature.Verify(certBytes)
		if err != nil {
			reply = unauthorizedError("Signature failed to validate")
			break
		}

		certs, err := x509.ParseCertificates(certBytes)
		if len(certs) < 1 {
			reply = malformedRequestError()
			break
		}
		err = wfe.RA.RevokeCertificate(*certs[0])
		if err != nil {
			reply = internalServerError()
			break
		}

		reply = AcmeMessage{Type: "revocation"}
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

*/
