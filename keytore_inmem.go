package keystore

import (
	"errors"
	"time"

	"go.zenithar.org/keystore/key"

	"github.com/patrickmn/go-cache"
)

type inMemoryKeyStore struct {
	store *cache.Cache
}

// NewInMemory returns an in-memory map based keystore
func NewInMemory(defaultExpiration, cleanupInterval time.Duration) (KeyStore, error) {
	return &inMemoryKeyStore{
		store: cache.New(defaultExpiration, cleanupInterval),
	}, nil
}

// -----------------------------------------------------------------------------
func (ks *inMemoryKeyStore) List() ([]key.Key, error) {
	var result []key.Key
	items := ks.store.Items()
	for _, i := range items {
		result = append(result, i.Object.(key.Key))
	}
	return result, nil
}

func (ks *inMemoryKeyStore) Add(k key.Key) error {
	return ks.store.Add(k.ID(), k, 24*time.Hour)
}

func (ks *inMemoryKeyStore) AddWithExpiration(k key.Key, exp time.Duration) error {
	return ks.store.Add(k.ID(), k, exp)
}

func (ks *inMemoryKeyStore) Get(id string) (key.Key, error) {
	k, found := ks.store.Get(id)
	if !found {
		return nil, errors.New("keystore: Key not found")
	}
	return k.(key.Key), nil
}

func (ks *inMemoryKeyStore) Remove(id string) error {
	ks.store.Delete(id)
	return nil
}

func (ks *inMemoryKeyStore) RotateKeys() error {
	ks.store.DeleteExpired()
	return nil
}
