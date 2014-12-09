// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package anvil

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

func (va ValidationAuthorityImpl) validateSimpleHTTPS(authz Authorization, index int) {
	identifier := authz.Validations[index].Identifier.Value
	challenge := authz.Validations[index].Challenge
	response := authz.Validations[index].Response

	if len(response.Path) == 0 {
		authz.Validations[index].Status = StatusInvalid
		va.RA.OnValidationUpdate(authz)
		return
	}

	// XXX: Local version; uncomment for real version
	url := fmt.Sprintf("http://localhost:5001/.well-known/acme-challenge/%s", response.Path)
	//url := fmt.Sprintf("https://%s/.well-known/acme-challenge/%s", identifier, response.Path)

	httpRequest, err := http.NewRequest("GET", url, nil)
	if err != nil {
		authz.Validations[index].Status = StatusInvalid
		va.RA.OnValidationUpdate(authz)
		return
	}

	httpRequest.Host = identifier
	client := http.Client{Timeout: 5 * time.Second}
	httpResponse, err := client.Do(httpRequest)

	if err == nil && httpResponse.StatusCode == 200 {
		// Read body & test
		body, err := ioutil.ReadAll(httpResponse.Body)
		if err != nil {
			authz.Validations[index].Status = StatusInvalid
			va.RA.OnValidationUpdate(authz)
			return
		}

		if bytes.Compare(body, []byte(challenge.Token)) == 0 {
			authz.Validations[index].Status = StatusValid
			va.RA.OnValidationUpdate(authz)
			return
		}
	}

	authz.Validations[index].Status = StatusInvalid
	va.RA.OnValidationUpdate(authz)
}

func (va ValidationAuthorityImpl) validateDvsni(authz Authorization, index int) {
	// identifier := val.Identifier.Value // XXX see below
	challenge := authz.Validations[index].Challenge
	response := authz.Validations[index].Response

	const DVSNI_SUFFIX = ".acme.invalid"
	nonceName := challenge.Nonce + DVSNI_SUFFIX

	R, err := b64dec(challenge.R)
	if err != nil {
		authz.Validations[index].Status = StatusInvalid
		va.RA.OnValidationUpdate(authz)
		return
	}
	S, err := b64dec(response.S)
	if err != nil {
		authz.Validations[index].Status = StatusInvalid
		va.RA.OnValidationUpdate(authz)
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
		authz.Validations[index].Status = StatusInvalid
		va.RA.OnValidationUpdate(authz)
		return
	}

	// Check that zName is a dNSName SAN in the server's certificate
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		authz.Validations[index].Status = StatusInvalid
		va.RA.OnValidationUpdate(authz)
		return
	}
	for _, name := range certs[0].DNSNames {
		if name == zName {
			authz.Validations[index].Status = StatusValid
			va.RA.OnValidationUpdate(authz)
			return
		}
	}

	authz.Validations[index].Status = StatusInvalid
	va.RA.OnValidationUpdate(authz)
}

func (va ValidationAuthorityImpl) UpdateValidations(authz Authorization) error {
	// Select the first supported validation method
	for i, val := range authz.Validations {
		switch val.Type {
		case "simpleHttps":
			go va.validateSimpleHTTPS(authz, i)
			return nil
		case "dvsni":
			go va.validateDvsni(authz, i)
			return nil
		}
	}

	return NotSupportedError("No supported validation method")
}
