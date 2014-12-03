package acme

import ()

type SimpleStorageAuthorityImpl struct {
	Storage map[Token]interface{}
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
