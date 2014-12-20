// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package anvil

import (
	"net/http"
	"testing"
)

// TODO: Unit tests on individual components

// WebAPI Test
// XXX Only for manual testing

const ENABLE_WEB = true

func TestWebAPI(t *testing.T) {
	if ENABLE_WEB {
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
		wfe.VA = &va
		ra.WFE = &wfe
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
