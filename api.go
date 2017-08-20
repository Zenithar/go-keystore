package keystore

import (
	"context"
	"time"

	"go.zenithar.org/keystore/key"
)

// Expirable is a behaviour for a key
type Expirable interface {
	ExpiresOn(time.Time)
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
	Generate(context.Context, key.Generator) (key.Key, error)
}

// -----------------------------------------------------------------------------

// keyHolder is the pointer to the current key
type keyHolder struct {
	Data       []byte `json:"data"`
	IssuedAt   int64  `json:"iat"`
	Expiration int64  `json:"exp"`
}

// IsExpired returns expiration status of the owned key
func (kh *keyHolder) IsExpired() bool {
	return time.Unix(kh.Expiration, 0).After(time.Now())
}

// ExpiresOn sets the expiration date of the holded key
func (kh *keyHolder) ExpiresOn(date time.Time) {
	kh.Expiration = date.UTC().Unix()
}

// NeverExpires disable holded key expiration
func (kh *keyHolder) NeverExpires() {
	kh.Expiration = 0
}
