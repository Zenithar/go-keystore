package key

import (
	"context"
	"fmt"
	"testing"

	prettyjson "github.com/hokaccha/go-prettyjson"
	. "github.com/onsi/gomega"
)

var (
	ctx = context.Background()
)

func TestEd25519_Generation(t *testing.T) {
	RegisterTestingT(t)

	key, _ := Ed25519(ctx)
	Expect(key.Algorithm()).To(Equal("Ed25519"))
	Expect(key.HasPrivate()).To(BeTrue())
	Expect(key.HasPublic()).To(BeTrue())

	pub := key.Public()
	Expect(pub.Algorithm()).To(Equal("Ed25519"))
	Expect(pub.HasPrivate()).To(BeFalse())
	Expect(pub.HasPublic()).To(BeTrue())
}

func TestEd25519_Deserialization(t *testing.T) {
	RegisterTestingT(t)

	key, err := toEd25519(&rawJWK{
		Algorithm:     "EC",
		Curve:         "Ed25519",
		KeyID:         "FYdFGFkduT7yJXkAMqF6BelQhS5tKaHWEBik0AhlxZ0",
		KeyType:       "OKP",
		X:             "uMQbnHrL3rVpBddEa9tgbRTS8OsjmgMOro8Ba2L0-ok",
		D:             "PFPV4ItiU2VbMTxdddWrGYlGtG6FzO26aVzFgbvwNRK4xBucesvetWkF10Rr22BtFNLw6yOaAw6ujwFrYvT6iQ",
		PublicKeyUse:  "sig",
		KeyOperations: []string{"sign", "verify"},
	})

	Expect(key).ToNot(BeNil())
	Expect(err).To(BeNil())

	s, _ := prettyjson.Marshal(key)
	fmt.Println(string(s))

	Expect(key.Algorithm()).To(Equal("Ed25519"))
	Expect(key.ID()).To(Equal("FYdFGFkduT7yJXkAMqF6BelQhS5tKaHWEBik0AhlxZ0"))
	Expect(key.HasPrivate()).To(BeTrue())
	Expect(key.HasPublic()).To(BeTrue())
}
