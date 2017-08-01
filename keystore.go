package keystore

import (
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
	All() ([]key.Key, error)
	OnlyPublicKeys() ([]key.Key, error)
	Add(key.Key) error
	AddWithExpiration(key.Key, time.Duration) error
	Get(string) (key.Key, error)
	Remove(string) error
	RotateKeys() error
	Pick() (key.Key, error)
	Generate() (key.Key, error)
}

// KeyGenerator is the key builder to use for the keystore
type KeyGenerator func() (key.Key, error)

// -----------------------------------------------------------------------------

var (
	// ErrNotImplemented is raised when calling not implemented method
	ErrNotImplemented = errors.New("keystore: Method not implemented")
	// ErrKeyNotFound is raised when trying to get inexistant key from keystore
	ErrKeyNotFound = errors.New("keystore: Key not found")
	// ErrGeneratorNeedPositiveValueAboveOne is raised when caller gives a value under 1 as count
	ErrGeneratorNeedPositiveValueAboveOne = errors.New("keystore: Key generation count needs positive above 1 value as count")
)
