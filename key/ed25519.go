package key

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"

	"golang.org/x/crypto/ed25519"
)

type ed25519Key struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

// Ed25519 key holder
func Ed25519() (Key, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	return &ed25519Key{
		priv: privateKey,
		pub:  publicKey,
	}, nil
}

func toEd25519(raw *rawJWK) (Key, error) {
	x, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(raw.X)
	if err != nil {
		return nil, err
	}

	if len(x) != ed25519.PublicKeySize {
		return nil, errors.New("key: invalid ed25519 public key size")
	}

	k := &ed25519Key{
		pub: x,
	}
	if len(raw.D) > 0 {
		d, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(raw.D)
		if err != nil {
			return nil, err
		}
		if len(d) != ed25519.PrivateKeySize {
			return nil, errors.New("key: invalid ed25519 private key size")
		}
		k.priv = d
	}

	return k, nil
}

// -----------------------------------------------------------------------------

func (k *ed25519Key) Algorithm() string {
	return "Ed25519"
}

func (k *ed25519Key) ID() string {
	return keyIDFromData(k.pub)
}

func (k *ed25519Key) HasPrivate() bool {
	return len(k.priv) > 0
}

func (k *ed25519Key) HasPublic() bool {
	return len(k.pub) > 0
}

func (k *ed25519Key) Public() Key {
	return &ed25519Key{
		pub: k.pub,
	}
}

// -----------------------------------------------------------------------------

func (k *ed25519Key) MarshalJSON() ([]byte, error) {
	r := &rawJWK{
		KeyID:     k.ID(),
		KeyType:   "OKP",
		Algorithm: "EC",
		Curve:     k.Algorithm(),
		X:         base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(k.pub),
	}
	if k.HasPrivate() {
		r.D = base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(k.priv)
	}

	return json.Marshal(r)
}
