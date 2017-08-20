package keystore

import (
	"context"
	"errors"
	"time"

	"go.zenithar.org/keystore/key"
)

// Expirable is a behaviour for a key
type Expirable interface {
	ExpiresAt(time.Time)
	IsExpired() bool
	NeverExpires()
}

// KeyStore contract
type KeyStore interface {
	All(context.Context) ([]key.Key, error)
	OnlyPublicKeys(context.Context) ([]key.Key, error)
	Add(context.Context, ...key.Key) error
	Get(context.Context, string) (key.Key, error)
	Remove(context.Context, string) error
	Generate(context.Context) (key.Key, error)
	Monitor(context.Context)
}

// -----------------------------------------------------------------------------

var (
	// ErrNotImplemented is raised when calling not implemented method
	ErrNotImplemented = errors.New("keystore: Method not implemented")
	// ErrKeyNotFound is raised when trying to get inexistant key from keystore
	ErrKeyNotFound = errors.New("keystore: Key not found")
	// ErrGeneratorNeedPositiveValueAboveOne is raised when caller gives a value under 1 as count
	ErrGeneratorNeedPositiveValueAboveOne = errors.New("keystore: Key generation count needs positive above 1 value as count")
)
