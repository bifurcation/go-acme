// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package anvil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"math/big"
)

// Utils

func bigint2base64(x *big.Int) string {
	return b64enc(x.Bytes())
}

func int2base64(x int) string {
	b := big.NewInt(int64(x))
	return bigint2base64(b)
}

func base642bigint(x string) (*big.Int, error) {
	data, err := b64dec(x)
	if err != nil {
		return nil, err
	}

	bn := big.NewInt(0)
	bn.SetBytes(data)
	return bn, nil
}

func base642int(x string) (int, error) {
	bn, err := base642bigint(x)
	if err != nil {
		return 0, err
	}

	return int(bn.Int64()), nil
}

func name2curve(name string) (elliptic.Curve, error) {
	switch name {
	case "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	}

	var dummy elliptic.Curve
	return dummy, NotFoundError("Unknown elliptic curve " + name)
}

func curve2name(curve elliptic.Curve) (string, error) {
	// XXX Assumes one curve per base field.  This is currently true for
	// the built-in curves in the 'elliptic' package
	p := curve.Params().P
	switch {
	case p.Cmp(elliptic.P256().Params().P) == 0:
		return "P-256", nil
	case p.Cmp(elliptic.P384().Params().P) == 0:
		return "P-384", nil
	case p.Cmp(elliptic.P521().Params().P) == 0:
		return "P-521", nil
	}

	return "", NotFoundError("Unknown elliptic curve")
}

// JWK

type rawJsonWebKey struct {
	// Only public key fields, since we only require verification
	KeyType string `json:"kty,omitempty"`
	N       string `json:"n,omitempty"`
	E       string `json:"e,omitempty"`
	Curve   string `json:"crv,omitempty"`
	X       string `json:"x,omitempty"`
	Y       string `json:"y,omitempty"`
}

type JsonWebKey struct {
	KeyType    string
	Rsa        *rsa.PublicKey
	Ec         *ecdsa.PublicKey
	Thumbprint string
}

func (jwk JsonWebKey) MarshalJSON() ([]byte, error) {
	raw := rawJsonWebKey{KeyType: jwk.KeyType}
	if jwk.Rsa != nil {
		raw.N = bigint2base64(jwk.Rsa.N)
		raw.E = int2base64(jwk.Rsa.E)
	}
	if jwk.Ec != nil {
		var err error
		raw.Curve, err = curve2name(jwk.Ec.Curve)
		if err != nil {
			return nil, err
		}

		raw.X = bigint2base64(jwk.Ec.X)
		raw.Y = bigint2base64(jwk.Ec.Y)
	}

	return json.Marshal(raw)
}

func (jwk *JsonWebKey) UnmarshalJSON(data []byte) error {
	var raw rawJsonWebKey
	err := json.Unmarshal(data, &raw)
	if err != nil {
		return err
	}

	jwk.KeyType = raw.KeyType
	switch jwk.KeyType {
	case "RSA":
		n, err := base642bigint(raw.N)
		if err != nil {
			return err
		}

		e, err := base642int(raw.E)
		if err != nil {
			return err
		}

		jwk.Rsa = &rsa.PublicKey{N: n, E: e}
		jwk.Thumbprint = raw.N
	case "EC":
		curve, err := name2curve(raw.Curve)
		if err != nil {
			return err
		}

		x, err := base642bigint(raw.X)
		if err != nil {
			return err
		}

		y, err := base642bigint(raw.Y)
		if err != nil {
			return err
		}

		jwk.Ec = &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
		jwk.Thumbprint = raw.X + raw.Y
	}

	return nil
}
