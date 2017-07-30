package keystore

import (
	"fmt"
	"testing"

	prettyjson "github.com/hokaccha/go-prettyjson"

	"go.zenithar.org/keystore/key"
)

func TestInMemoryKeystore(t *testing.T) {
	ks, _ := NewInMemory()

	k1, _ := key.Ed25519()
	ks.Add(k1)
	k2, _ := key.Ed25519()
	ks.Add(k2)

	kl, _ := ks.OnlyPublicKeys()
	s, _ := prettyjson.Marshal(kl)
	fmt.Println(string(s))
}
