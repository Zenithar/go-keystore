package keystore

import (
	"context"
	"testing"
	"time"

	"go.zenithar.org/keystore/backends/inmemory"
	"go.zenithar.org/keystore/key"
)

func TestInMemoryKeyStore(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	backend, _ := inmemory.New()
	ks, _ := New(WithGenerator(key.Ed25519), WithBackend(backend), WithInterval(10))
	go ks.Monitor(ctx)

	// Generates keys
	k1, _ := ks.Generate(ctx)
	k2, _ := ks.Generate(ctx)

	// Add to keystore
	err := ks.Add(ctx, k1, k2.Public())
	if err != nil {
		t.Errorf("Keystore : no error when adding should occurs, %v", err)
	}

	// Expose all
	keys, _ := ks.All(ctx)
	if len(keys) != 2 {
		t.Fatalf("Keystore must have 2 keys, actually %d.", len(keys))
	}

	// Get all keys
	for _, k := range keys {
		keyObject, _ := ks.Get(ctx, k.ID())

		if keyObject == nil {
			t.Fatal("Keystore : invalid key retrieval")
		}
	}

	// Get all public keys
	publicKeys, _ := ks.OnlyPublicKeys(ctx)
	for _, k := range publicKeys {
		keyObject, _ := ks.Get(ctx, k.ID())

		if keyObject == nil {
			t.Fatal("Keystore : invalid key retrieval")
		}
		if keyObject.HasPrivate() {
			t.Fatal("Keystore : should contain only public key in result")
		}
	}

	// Remove a key
	ks.Remove(ctx, k2.ID())

	time.Sleep(500 * time.Millisecond)
}
