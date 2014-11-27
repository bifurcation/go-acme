package acme

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

type AcmeChallenge struct {
	Type  string `json:"type"`
	Token string `json:"token"` // SimpleHTTPS
	R     string `json:"r"`     // DVSNI
	Nonce string `json:"nonce"`
}

type AcmeResponse struct {
	Type  string `json:"type"`
	Token string `json:"token"` // SimpleHTTPS
	Path  string `json:"path"`  //
	S     string `json:"s"`     // DVSNI
}

func SimpleHTTPSChallenge() AcmeChallenge {
	return AcmeChallenge{
		Type:  "simpleHttps",
		Token: newToken(),
	}
}

func DvsniChallenge() AcmeChallenge {
	nonce := make([]byte, 16)
	rand.Read(nonce)
	return AcmeChallenge{
		Type:  "dvsni",
		R:     randomString(32),
		Nonce: hex.EncodeToString(nonce),
	}
}

func ValidateSimpleHTTPS(acme *AcmeWebAPI, deferralToken string, identifier string, challenge AcmeChallenge, response AcmeResponse) {
	var responseMessage AcmeMessage

	if len(response.Path) == 0 {
		responseMessage = unauthorizedError("malformed simpleHttps response")
		acme.ProvideDeferredResponse(deferralToken, responseMessage)
		return
	}

	// XXX: Local version; uncomment for real version
	url := fmt.Sprintf("http://localhost:5001/.well-known/acme-challenge/%s", response.Path)
	//url := fmt.Sprintf("https://%s/.well-known/acme-challenge/%s", identifier, response.Path)

	httpRequest, err := http.NewRequest("GET", url, nil)
	// XXX Ignore err here.  What could go wrong?
	httpRequest.Host = identifier
	client := http.Client{Timeout: 5 * time.Second}
	httpResponse, err := client.Do(httpRequest)

	if err != nil {
		responseMessage = unauthorizedError("Unable to fetch simpleHttps URL")
		acme.ProvideDeferredResponse(deferralToken, responseMessage)
		return
	} else if httpResponse.StatusCode == 200 {
		// Read body & test
		body, err := ioutil.ReadAll(httpResponse.Body)
		if err != nil {
			responseMessage = unauthorizedError("Unable to read simpleHttps response body")
			acme.ProvideDeferredResponse(deferralToken, responseMessage)
			return
		}

		if bytes.Compare(body, []byte(challenge.Token)) == 0 {
			responseMessage = AcmeMessage{
				Type:       "authorization",
				Identifier: identifier,
			}
			acme.ProvideDeferredResponse(deferralToken, responseMessage)
			return
		} else {
			responseMessage = unauthorizedError(fmt.Sprintf("Unrecognized body [%s], expected [%s]", string(body), challenge.Token))
			acme.ProvideDeferredResponse(deferralToken, responseMessage)
			return
		}
	}

	responseMessage = unauthorizedError(fmt.Sprintf("HTTP error on simpleHttps: %d", httpResponse.StatusCode))
}

func ValidateDvsni(acme *AcmeWebAPI, deferralToken string, identifier string, challenge AcmeChallenge, response AcmeResponse) {
	var responseMessage AcmeMessage
	defer acme.ProvideDeferredResponse(deferralToken, responseMessage)

	const DVSNI_SUFFIX = ".acme.invalid"
	nonceName := challenge.Nonce + DVSNI_SUFFIX

	R, err := b64dec(challenge.R)
	if err != nil {
		responseMessage = internalServerError()
		acme.ProvideDeferredResponse(deferralToken, responseMessage)
		return
	}
	S, err := b64dec(response.S)
	if err != nil {
		responseMessage = malformedRequestError()
		acme.ProvideDeferredResponse(deferralToken, responseMessage)
		return
	}
	RS := append(R, S...)

	sha := sha256.New()
	sha.Write(RS)
	z := make([]byte, sha.Size())
	sha.Sum(z)
	zName := hex.EncodeToString(z)

	// Make a connection with SNI = nonceName
	hostPort := "localhost:5001"
	//hostPort := identifier + ":443"
	conn, err := tls.Dial("tcp", hostPort, &tls.Config{
		ServerName:         nonceName,
		InsecureSkipVerify: true,
	})

	if err != nil {
		responseMessage = unauthorizedError("Unable to connect to DVSNI server")
		acme.ProvideDeferredResponse(deferralToken, responseMessage)
		return
	}

	// Check that zName is a dNSName SAN in the server's certificate
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		responseMessage = unauthorizedError("DVSNI server provided no certificate")
		acme.ProvideDeferredResponse(deferralToken, responseMessage)
		return
	}
	for _, name := range certs[0].DNSNames {
		if name == zName {
			responseMessage = AcmeMessage{
				Type:       "authorization",
				Identifier: identifier,
			}
			acme.ProvideDeferredResponse(deferralToken, responseMessage)
			return
		}
	}

	responseMessage = unauthorizedError("DVSNI certificate did not contain proper name")
	acme.ProvideDeferredResponse(deferralToken, responseMessage)
}

func nullResponse(response AcmeResponse) bool {
	// null values unmarshal to default values
	return len(response.Type) == 0
}

func ValidateChallenges(acme *AcmeWebAPI, deferralToken string, identifier string, challenges []AcmeChallenge, responses []AcmeResponse) {
	// Pause for 2sec to allow the other sie to start up
	time.Sleep(2 * time.Second)

	// Validate the first challenge we see of a type we support
	for i := range challenges {
		if nullResponse(responses[i]) {
			continue
		}

		switch responses[i].Type {
		case "simpleHttps":
			ValidateSimpleHTTPS(acme, deferralToken, identifier, challenges[i], responses[i])
			return
		case "dvsni":
			ValidateDvsni(acme, deferralToken, identifier, challenges[i], responses[i])
			return
		}
	}

	acme.ProvideDeferredResponse(deferralToken,
		unauthorizedError("No supported challenge/response pairs found"))
}
