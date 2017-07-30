package keystore

import (
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
	List() ([]key.Key, error)
	Add(key.Key) error
	AddWithExpiration(key.Key, time.Duration) error
	Get(string) (key.Key, error)
	Remove(string) error
	RotateKeys() error
}
