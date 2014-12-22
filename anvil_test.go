// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package anvil

import (
	"log"
	"net/http"
	"testing"
)

// TODO: Unit tests on individual components

// WebAPI Test
// XXX Only for manual testing

const ENABLE_WEB = false

func TestWebAPI(t *testing.T) {
	if ENABLE_WEB {
		log.Printf(" [*] Running WebAPI")

		// Create the components
		wfe := NewWebFrontEndImpl()
		sa := NewSimpleStorageAuthorityImpl()
		ra := NewRegistrationAuthorityImpl()
		va := NewValidationAuthorityImpl()
		ca, err := NewCertificateAuthorityImpl()
		if err != nil {
			t.Errorf("Failed to generate CA")
			return
		}

		// Wire them up
		wfe.RA = &ra
		wfe.SA = &sa
		ra.CA = &ca
		ra.SA = &sa
		ra.VA = &va
		va.RA = &ra

		// Go!
		authority := "localhost:4000"
		authzPath := "/acme/authz/"
		certPath := "/acme/cert/"
		wfe.SetAuthzBase("http://" + authority + authzPath)
		wfe.SetCertBase("http://" + authority + certPath)
		http.HandleFunc("/acme/new-authz", wfe.NewAuthz)
		http.HandleFunc("/acme/new-cert", wfe.NewCert)
		http.HandleFunc("/acme/authz/", wfe.Authz)
		http.HandleFunc("/acme/cert/", wfe.Cert)
		http.ListenAndServe("localhost:4000", nil)
	}
}

// WebAPI Test with AMQP
// XXX Only for manual testing

const ENABLE_WEB_AMQP = true

func TestWebAPIAMQP(t *testing.T) {
	if ENABLE_WEB_AMQP {
		log.Printf(" [*] Running WebAPI with AMQP")

		// Create an AMQP channel
		ch, err := amqpConnect("amqp://guest:guest@localhost:5672")
		if err != nil {
			t.Errorf("Failed to create AMQP connection")
			return
		}

		// Create AMQP-RPC clients for CA, VA, RA, SA
		cac, err := NewCertificateAuthorityClient("CA.client", "CA.server", ch)
		if err != nil {
			t.Errorf("Failed to generate CA client")
			return
		}
		vac, err := NewValidationAuthorityClient("VA.client", "VA.server", ch)
		if err != nil {
			t.Errorf("Failed to generate VA client")
			return
		}
		rac, err := NewRegistrationAuthorityClient("RA.client", "RA.server", ch)
		if err != nil {
			t.Errorf("Failed to generate RA client")
			return
		}
		sac, err := NewStorageAuthorityClient("SA.client", "SA.server", ch)
		if err != nil {
			t.Errorf("Failed to generate SA client")
			return
		}

		// ... and corresponding servers
		// (We need this order so that we can give the servers
		//  references to the clients)
		cas, err := NewCertificateAuthorityServer("CA.server", ch)
		if err != nil {
			t.Errorf("Failed to generate CA server")
			return
		}
		vas, err := NewValidationAuthorityServer("VA.server", ch, &rac)
		if err != nil {
			t.Errorf("Failed to generate VA server")
			return
		}
		ras, err := NewRegistrationAuthorityServer("RA.server", ch, &vac, &cac, &sac)
		if err != nil {
			t.Errorf("Failed to generate RA server")
			return
		}
		sas := NewStorageAuthorityServer("SA.server", ch)
		if err != nil {
			t.Errorf("Failed to generate SA server")
			return
		}

		// Start the servers
		cas.Start()
		vas.Start()
		ras.Start()
		sas.Start()

		// Wire up the front end (wrappers are already wired)
		wfe := NewWebFrontEndImpl()
		wfe.RA = &rac
		wfe.SA = &sac

		// Go!
		authority := "localhost:4000"
		authzPath := "/acme/authz/"
		certPath := "/acme/cert/"
		wfe.SetAuthzBase("http://" + authority + authzPath)
		wfe.SetCertBase("http://" + authority + certPath)
		http.HandleFunc("/acme/new-authz", wfe.NewAuthz)
		http.HandleFunc("/acme/new-cert", wfe.NewCert)
		http.HandleFunc("/acme/authz/", wfe.Authz)
		http.HandleFunc("/acme/cert/", wfe.Cert)
		http.ListenAndServe("localhost:4000", nil)
	}
}
