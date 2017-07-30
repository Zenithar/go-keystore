package keystore

import (
	"sync"
	"time"

	"go.zenithar.org/keystore/key"
)

type inMemoryKeyStore struct {
	sync.RWMutex

	store map[string]key.Key
}

// NewInMemory returns an in-memory map based keystore
func NewInMemory() (KeyStore, error) {
	store := make(map[string]key.Key)
	return &inMemoryKeyStore{
		store: store,
	}, nil
}

// -----------------------------------------------------------------------------
func (ks *inMemoryKeyStore) All() ([]key.Key, error) {
	ks.RLock()
	defer ks.RUnlock()

	var result []key.Key
	for _, i := range ks.store {
		result = append(result, i)
	}
	return result, nil
}

func (ks *inMemoryKeyStore) OnlyPublicKeys() ([]key.Key, error) {
	ks.RLock()
	defer ks.RUnlock()

	var result []key.Key
	for _, i := range ks.store {
		result = append(result, i.Public())
	}
	return result, nil
}

func (ks *inMemoryKeyStore) Add(k key.Key) error {
	ks.Lock()
	ks.store[k.ID()] = k
	ks.Unlock()

	return nil
}

func (ks *inMemoryKeyStore) AddWithExpiration(k key.Key, exp time.Duration) error {
	ks.Lock()
	ks.store[k.ID()] = k
	ks.Unlock()

	return nil
}

func (ks *inMemoryKeyStore) Get(id string) (key.Key, error) {
	ks.RLock()
	defer ks.RUnlock()

	if _, ok := ks.store[id]; !ok {
		return nil, ErrKeyNotFound
	}
	return ks.store[id], nil
}

func (ks *inMemoryKeyStore) Remove(id string) error {
	ks.Lock()
	delete(ks.store, id)
	ks.Unlock()
	return nil
}

func (ks *inMemoryKeyStore) RotateKeys() error {
	return nil
}
