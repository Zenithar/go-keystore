package keystore

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.zenithar.org/keystore/key"
)

type inMemoryKeyStore struct {
	sync.RWMutex

	generator KeyGenerator
	store     map[string]key.Key
	keys      []string
	count     int
	pick      int
}

// NewInMemory returns an in-memory map based keystore
func NewInMemory(generator KeyGenerator) (KeyStore, error) {
	store := make(map[string]key.Key)
	return &inMemoryKeyStore{
		store:     store,
		generator: generator,
		pick:      0,
		count:     0,
	}, nil
}

// -----------------------------------------------------------------------------
func (ks *inMemoryKeyStore) Generate() (key.Key, error) {
	k, err := ks.generator()
	if err != nil {
		return nil, fmt.Errorf("keystore: Key generation error %v", err)
	}

	return k, nil
}

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

func (ks *inMemoryKeyStore) Pick() (key.Key, error) {
	// Round robin
	ks.pick = (ks.pick + 1) % (len(ks.keys))
	return ks.store[ks.keys[ks.pick]], nil
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

func (ks *inMemoryKeyStore) RotateKeys(ctx context.Context) error {
	return nil
}
