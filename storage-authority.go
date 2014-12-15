// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package anvil

import (
	"fmt"
)

type SimpleStorageAuthorityImpl struct {
	Storage map[Token]interface{}
}

func (sa *SimpleStorageAuthorityImpl) dumpState() {
	fmt.Printf("Storage state: \n%+v\n", sa.Storage)
}

func NewSimpleStorageAuthorityImpl() SimpleStorageAuthorityImpl {
	return SimpleStorageAuthorityImpl{
		Storage: make(map[Token]interface{}),
	}
}

func (sa *SimpleStorageAuthorityImpl) Put(object interface{}) (Token, error) {
	token := Token(newToken())
	err := sa.Update(token, object)
	return token, err
}

func (sa *SimpleStorageAuthorityImpl) Update(token Token, object interface{}) error {
	sa.Storage[token] = object
	return nil
}

func (sa *SimpleStorageAuthorityImpl) Get(token Token) (interface{}, error) {
	value, ok := sa.Storage[token]
	if ok {
		return value, nil
	} else {
		return struct{}{}, NotFoundError("Unknown storage token")
	}
}
