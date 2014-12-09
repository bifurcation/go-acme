// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package anvil

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"testing"
)

// Base64 Tests

func TestB64Enc(t *testing.T) {
	fmt.Println("--> TestB64Enc")
	in := []byte{0x00, 0xff}
	out := "AP8"
	if x := b64enc(in); x != out {
		t.Errorf("b64enc(%v) = %v, want %v", in, x, out)
	}
}

func TestB64Dec(t *testing.T) {
	fmt.Println("--> TestB64Dec")
	in := "_wA"
	out := []byte{0xFF, 0x00}
	x, err := b64dec(in)
	if (err != nil) || (bytes.Compare(x, out) != 0) {
		t.Errorf("b64dec(%v) = %v, want %v", in, x, out)
	}
}

// JWK Tests (from draft-ietf-jose-cookbook)

func TestRsaJwk(t *testing.T) {
	fmt.Println("--> TestRsaJwk")
	in := `{
    "kty": "RSA",
     "n": "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw",
     "e": "AQAB"
  }`
	var out JsonWebKey
	err := json.Unmarshal([]byte(in), &out)
	if err != nil {
		t.Errorf("JSON unmarshal error: %+v", err)
		return
	}

	if out.KeyType != "RSA" {
		t.Errorf("Incorrect key type %+v, expecting %+v", out.KeyType, "RSA")
		return
	}

	if out.Rsa == nil {
		t.Errorf("RSA key not present")
		return
	}

	if out.Rsa.E != 0x010001 {
		t.Errorf("Incorrect public exponent %+v, expecting %+v", out.Rsa.E, 0x010001)
		return
	}

	nBytes := []byte{
		0x9f, 0x81, 0x0f, 0xb4, 0x03, 0x82, 0x73, 0xd0, 0x25, 0x91, 0xe4, 0x07, 0x3f, 0x31, 0xd2, 0xb6,
		0x00, 0x1b, 0x82, 0xce, 0xdb, 0x4d, 0x92, 0xf0, 0x50, 0x16, 0x5d, 0x47, 0xcf, 0xca, 0xb8, 0xa3,
		0xc4, 0x1c, 0xb7, 0x78, 0xac, 0x75, 0x53, 0x79, 0x3f, 0x8e, 0xf9, 0x75, 0x76, 0x8d, 0x1a, 0x23,
		0x74, 0xd8, 0x71, 0x25, 0x64, 0xc3, 0xbc, 0xd7, 0x7b, 0x9e, 0xa4, 0x34, 0x54, 0x48, 0x99, 0x40,
		0x7c, 0xff, 0x00, 0x99, 0x92, 0x0a, 0x93, 0x1a, 0x24, 0xc4, 0x41, 0x48, 0x52, 0xab, 0x29, 0xbd,
		0xb0, 0xa9, 0x5c, 0x06, 0x53, 0xf3, 0x6c, 0x60, 0xe6, 0x0b, 0xf9, 0x0b, 0x62, 0x58, 0xdd, 0xa5,
		0x6f, 0x37, 0x04, 0x7b, 0xa5, 0xc2, 0xd1, 0xd0, 0x29, 0xaf, 0x9c, 0x9d, 0x40, 0xba, 0xc7, 0xaa,
		0x41, 0xc7, 0x8a, 0x0d, 0xd1, 0x06, 0x8a, 0xdd, 0x69, 0x9e, 0x80, 0x8f, 0xea, 0x01, 0x1e, 0xa1,
		0x44, 0x1d, 0x8a, 0x4f, 0x7b, 0xb4, 0xe9, 0x7b, 0xe3, 0x9f, 0x55, 0xf1, 0xdd, 0xd4, 0x4e, 0x9c,
		0x4b, 0xa3, 0x35, 0x15, 0x97, 0x03, 0xd4, 0xd3, 0x4b, 0x60, 0x3e, 0x65, 0x14, 0x7a, 0x4f, 0x23,
		0xd6, 0xd3, 0xc0, 0x99, 0x6c, 0x75, 0xed, 0xee, 0x84, 0x6a, 0x82, 0xd1, 0x90, 0xae, 0x10, 0x78,
		0x3c, 0x96, 0x1c, 0xf0, 0x38, 0x7a, 0xed, 0x21, 0x06, 0xd2, 0xd0, 0x55, 0x5b, 0x6f, 0xd9, 0x37,
		0xfa, 0xd5, 0x53, 0x53, 0x87, 0xe0, 0xff, 0x72, 0xff, 0xbe, 0x78, 0x94, 0x14, 0x02, 0xb0, 0xb8,
		0x22, 0xea, 0x2a, 0x74, 0xb6, 0x05, 0x8c, 0x1d, 0xab, 0xf9, 0xb3, 0x4a, 0x76, 0xcb, 0x63, 0xb8,
		0x7f, 0xaa, 0x2c, 0x68, 0x47, 0xb8, 0xe2, 0x83, 0x7f, 0xff, 0x91, 0x18, 0x6e, 0x6b, 0x1c, 0x14,
		0x91, 0x1c, 0xf9, 0x89, 0xa8, 0x90, 0x92, 0xa8, 0x1c, 0xe6, 0x01, 0xdd, 0xac, 0xd3, 0xf9, 0xcf}
	n := big.NewInt(0)
	n.SetBytes(nBytes)
	if out.Rsa.N.Cmp(n) != 0 {
		t.Errorf("Incorrect modulus %+v, expecting %+v", out.Rsa.N, n)
		return
	}
}

func TestEcJwk(t *testing.T) {
	fmt.Println("--> TestEcJwk")
	in := `{
     "kty": "EC",
     "crv": "P-521",
     "x": "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt",
     "y": "AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1"
   }`
	var out JsonWebKey
	err := json.Unmarshal([]byte(in), &out)
	if err != nil {
		t.Errorf("JSON unmarshal error: %+v", err)
		return
	}

	if out.KeyType != "EC" {
		t.Errorf("Incorrect key type %+v, expecting %+v", out.KeyType, "RSA")
		return
	}

	if out.Ec == nil {
		t.Errorf("EC key not present")
		return
	}

	if out.Ec.Curve.Params().BitSize != 521 {
		t.Errorf("Incorrect curve size %+v, expecting %+v", out.Ec.Curve.Params().BitSize, 521)
		return
	}

	xBytes := []byte{
		0x00, 0x72, 0x99, 0x2c, 0xb3, 0xac, 0x08, 0xec, 0xf3, 0xe5, 0xc6,
		0x3d, 0xed, 0xec, 0x0d, 0x51, 0xa8, 0xc1, 0xf7, 0x9e, 0xf2, 0xf8,
		0x2f, 0x94, 0xf3, 0xc7, 0x37, 0xbf, 0x5d, 0xe7, 0x98, 0x66, 0x71,
		0xea, 0xc6, 0x25, 0xfe, 0x82, 0x57, 0xbb, 0xd0, 0x39, 0x46, 0x44,
		0xca, 0xaa, 0x3a, 0xaf, 0x8f, 0x27, 0xa4, 0x58, 0x5f, 0xbb, 0xca,
		0xd0, 0xf2, 0x45, 0x76, 0x20, 0x08, 0x5e, 0x5c, 0x8f, 0x42, 0xad}
	x := big.NewInt(0)
	x.SetBytes(xBytes)
	if out.Ec.X.Cmp(x) != 0 {
		t.Errorf("Incorrect X-coordinate %+v, expecting %+v", out.Ec.X, x)
		return
	}

	yBytes := []byte{
		0x01, 0xdc, 0xa6, 0x94, 0x7b, 0xce, 0x88, 0xbc, 0x57, 0x90, 0x48,
		0x5a, 0xc9, 0x74, 0x27, 0x34, 0x2b, 0xc3, 0x5f, 0x88, 0x7d, 0x86,
		0xd6, 0x5a, 0x08, 0x93, 0x77, 0xe2, 0x47, 0xe6, 0x0b, 0xaa, 0x55,
		0xe4, 0xe8, 0x50, 0x1e, 0x2a, 0xda, 0x57, 0x24, 0xac, 0x51, 0xd6,
		0x90, 0x90, 0x08, 0x03, 0x3e, 0xbc, 0x10, 0xac, 0x99, 0x9b, 0x9d,
		0x7f, 0x5c, 0xc2, 0x51, 0x9f, 0x3f, 0xe1, 0xea, 0x1d, 0x94, 0x75}
	y := big.NewInt(0)
	y.SetBytes(yBytes)
	if out.Ec.Y.Cmp(y) != 0 {
		t.Errorf("Incorrect X-coordinate %+v, expecting %+v", out.Ec.Y, y)
		return
	}
}

// Legacy signature tests

func TestLegacySignature(t *testing.T) {
	fmt.Println("--> TestLegacySignature")
	in := `
  {
    "alg": "RS256",
    "nonce": "4EtbQdg_PyhjmaTOaEGXig",
    "sig": "GBf-WmDMesuhx9FN_ScjkSz7efEP6nDs1lMWBeeBOsdtT9MB_oI5BbBU80rSJ9AvySp8_AFZ7gyIyilfvlZIA_9YHAfHwSo2qEMMTOraoWAJ7VYr1tR4J4axGXrI9LLVUdwwaED4DM2MUGSDYOTjPvWqvaeGP2QW3t-VhH3dnn2xqg39eHiJ4O6c8Lfz1sT2XsMBNa2nPA4MVOtsQbjls5FLf07JvBbro4acuMQWm7sAz4PHj3nst4wSN5q2WPQdlHYVbOD0J2HBPfBmEJdUJYCTaYu2w32Ao_8BRu4oTvTOVRajfXL6n15YG6CTDh_mtEQ0jDcr4WHAxTJPUus_aA",
    "jwk": {
      "kty": "RSA",
      "n": "o6SZr4OGVRN9cpG5axNueQT3yj0TeAwpXdFdootTdGXKuTVYdeOQzLpshizY8PhJN66WvG8rt5PjT4vb0jy8t9LaIBKjUUbi8-0TpAkPLdEEcT8J5MjYhFKU2GDpg8EJ0JuAjapIaAZvVdruWKdpCM3k-LZ0yqZHGz5xT3RoVVWhDgwdaK3wkhEHfYmFtC5Ok6fIRkysUQDtHoI_I9hVevsSYYT0UkMmhN-YYlNC2JSCrAg9N0A2WAS5O0UZN91D3gAX13ouFpEMr4Rj1sCokzBMEZiyljjvhq-TIBJ4ImRMuEQXauxp85Dd_mrpverHZKcRfpGirEpxhvtU3bySUQ",
      "e": "AQAB"
    }
  }`

	csr, err := b64dec(`MIICWzCCAUMCAQAwFjEUMBIGA1UEAxMLZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCDVV8MK2rp3bQYmq-jrZEDdIBl8qmi2YXMSjw9rTwJpZKsyxXp6n_j48KY8DDl5M570X1_lAohawLVohw8YlkKHgheQMuCqTl-BOqLzzRg92hu4N29sxpwYDWWHm-9Afznsh9FED2cbi-tF0L4YIM23cwig-g1y0ts3mAYP-8UlGSwK1iXaaFNzqHPfI7_SDO_IaIzWaTMZY2z6dUlTHNfAIy-7unjTJr3aj9rEL7JU9hkxGaOf9ST4pmhGx7lfJFW2GdZ0wE0fXLQvhQDmXWnrNO7jwBTKlL9T_3XpJErUNwZVyi-npUmmgtMjvXcMC5h29ThSXAcpULvJ5gZe2HXAgMBAAGgADANBgkqhkiG9w0BAQUFAAOCAQEAIxXlkjYiu28kGKgIjP9r7vxhjQNEc225f5wpA6rapYP029Yd0c7o-W22b6UwUoErt_3zc6cYnWBm8F5ED4AXuoYZfm6Xgqvynq_t9lvL1O6Du0vTdHOj2V-MEVDZsAcjL-uMxh_7Hzi0ucPm1oXTBTml3Zr6KSNXDUloRoYJrCgRecxuP1uauZ8HKk-GfYWycWbtsPzFAjpblMChHwxOYTb-bgd79cGs9Mjia8EimLuh1g4bXGKTYIjZ6Q4Pitfz82kRzQuF8tDDWc9yACk3C5re3iSDAj6zRiDBaId_tkDr6IrF803l0PE6lwEVjT5OowjdmBZ5VDnkicA647ACtA`)
	if err != nil {
		t.Errorf("b64 decode error: %+v", err)
		return
	}

	var out LegacyAcmeSignature
	err = json.Unmarshal([]byte(in), &out)

	if err != nil {
		t.Errorf("JSON unmarshal error: %+v", err)
		return
	}

	err = out.Verify(csr)
	if err != nil {
		t.Errorf("Signature failed verification: %+v", err)
		return
	}
}

// WebAPI Tests
// XXX Only for manual testing

const ENABLE_WEB = true

func TestWebAPI(t *testing.T) {
	if ENABLE_WEB {
		fmt.Println("--> TestWebAPI")

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
		va.RA = &ra

		// Go!
		http.Handle("/acme", wfe)
		http.ListenAndServe("localhost:4000", nil)
	}
}
