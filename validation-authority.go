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

type ValidationAuthorityImpl struct {
	RA RegistrationAuthority
}

func NewValidationAuthorityImpl() ValidationAuthorityImpl {
	return ValidationAuthorityImpl{}
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

func (va ValidationAuthorityImpl) validateSimpleHTTPS(val Validation) {
	identifier := val.Identifier.Value
	challenge := val.Challenge
	response := val.Response

	if len(response.Path) == 0 {
		val.Status = StatusInvalid
		va.RA.OnValidationUpdate(val)
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

	if err == nil && httpResponse.StatusCode == 200 {
		// Read body & test
		body, err := ioutil.ReadAll(httpResponse.Body)
		if err != nil {
			val.Status = StatusInvalid
			va.RA.OnValidationUpdate(val)
			return
		}

		if bytes.Compare(body, []byte(challenge.Token)) == 0 {
			val.Status = StatusValid
			va.RA.OnValidationUpdate(val)
			return
		}
	}

	val.Status = StatusInvalid
	va.RA.OnValidationUpdate(val)
}

func (va ValidationAuthorityImpl) validateDvsni(val Validation) {
	// identifier := val.Identifier.Value // see below
	challenge := val.Challenge
	response := val.Response

	const DVSNI_SUFFIX = ".acme.invalid"
	nonceName := challenge.Nonce + DVSNI_SUFFIX

	R, err := b64dec(challenge.R)
	if err != nil {
		val.Status = StatusInvalid
		va.RA.OnValidationUpdate(val)
		return
	}
	S, err := b64dec(response.S)
	if err != nil {
		val.Status = StatusInvalid
		va.RA.OnValidationUpdate(val)
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
		val.Status = StatusInvalid
		va.RA.OnValidationUpdate(val)
		return
	}

	// Check that zName is a dNSName SAN in the server's certificate
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		val.Status = StatusInvalid
		va.RA.OnValidationUpdate(val)
		return
	}
	for _, name := range certs[0].DNSNames {
		if name == zName {
			val.Status = StatusValid
			va.RA.OnValidationUpdate(val)
			return
		}
	}

	val.Status = StatusInvalid
	va.RA.OnValidationUpdate(val)
}

func (va ValidationAuthorityImpl) UpdateValidation(val Validation) error {
	switch val.Type {
	case "simpleHttps":
		go va.validateSimpleHTTPS(val)
		return nil
	case "dvsni":
		go va.validateDvsni(val)
		return nil
	}

	return NotSupportedError("Unsupported validation method " + val.Type)
}
