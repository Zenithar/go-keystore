package keystore

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"go.zenithar.org/keystore/backends"
	"go.zenithar.org/keystore/key"
)

type defaultKeyStore struct {
	sync.RWMutex

	generator key.Generator
	store     backends.Backend
	interval  uint64

	keys map[string]key.Key
}

// New returns a default keystore implementation instance
func New(opts ...Option) (KeyStore, error) {
	// Default Options
	options := &Options{
		Generator: key.Ed25519,
		Backend:   nil,
		Interval:  60,
	}

	// Overrides with option
	for _, opt := range opts {
		opt(options)
	}

	// Initializes default value
	ks := &defaultKeyStore{
		generator: options.Generator,
		store:     options.Backend,
		interval:  options.Interval,
		keys:      make(map[string]key.Key),
	}

	// Synchronize with backend
	return ks, ks.synchronize(context.Background())
}

// -----------------------------------------------------------------------------
func (ks *defaultKeyStore) Generate(context.Context) (key.Key, error) {
	k, err := ks.generator()
	if err != nil {
		return nil, fmt.Errorf("keystore: Key generation error %v", err)
	}

	return k, nil
}

func (ks *defaultKeyStore) All(ctx context.Context) ([]key.Key, error) {
	ks.RLock()
	defer ks.RUnlock()

	var result []key.Key
	for _, i := range ks.keys {
		result = append(result, i)
	}

	return result, nil
}

func (ks *defaultKeyStore) OnlyPublicKeys(ctx context.Context) ([]key.Key, error) {
	ks.RLock()
	defer ks.RUnlock()

	var result []key.Key
	for _, i := range ks.keys {
		result = append(result, i.Public())
	}

	return result, nil
}

func (ks *defaultKeyStore) Add(ctx context.Context, keys ...key.Key) error {
	for _, k := range keys {
		// Marshal only public key to json
		payload, err := json.Marshal(k.Public())
		if err != nil {
			return fmt.Errorf("keystore: Unable to marshal key as JSON: %v", err)
		}

		// Add to backend
		err = ks.store.Set(ctx, fmt.Sprintf("jwk/%s", k.ID()), payload)
		if err != nil {
			return fmt.Errorf("keystore: Unable to save key to backend: %v", err)
		}
	}

	// Synchronize the local cache
	return ks.synchronize(ctx)
}

func (ks *defaultKeyStore) Get(ctx context.Context, id string) (key.Key, error) {
	ks.RLock()
	defer ks.RUnlock()

	if _, ok := ks.keys[id]; !ok {
		return nil, ErrKeyNotFound
	}

	return ks.keys[id], nil
}

func (ks *defaultKeyStore) Remove(ctx context.Context, id string) error {
	if _, ok := ks.keys[id]; ok {
		delete(ks.keys, id)
		return nil
	}

	return ErrKeyNotFound
}

func (ks *defaultKeyStore) Monitor(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Duration(ks.interval) * time.Second):
			ks.synchronize(ctx)
		default:
		}
	}
}

// -----------------------------------------------------------------------------

func (ks *defaultKeyStore) synchronize(ctx context.Context) error {
	keys, err := ks.store.List(ctx, "jwk")
	if err != nil {
		return fmt.Errorf("keystore: Unable to synchronize keystore with backend")
	}

	for _, kid := range keys {
		// Retrieve each value
		value, err := ks.store.Get(ctx, fmt.Sprintf("jwk/%s", kid))
		if err != nil {
			continue
		}

		// Decode value as Key
		k, err := key.FromString(value)
		if err != nil {
			continue
		}

		// Add key to local cache
		ks.Lock()
		ks.keys[k.ID()] = k
		ks.Unlock()
	}

	return nil
}
