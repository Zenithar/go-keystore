package keystore

import (
	"fmt"
	"testing"

	prettyjson "github.com/hokaccha/go-prettyjson"

	"go.zenithar.org/keystore/key"
)

func TestInMemoryKeystore(t *testing.T) {
	ks, _ := NewInMemory(key.Ed25519)
	ks.Generate(4)

	kl, _ := ks.OnlyPublicKeys()
	s, _ := prettyjson.Marshal(kl)
	fmt.Println(string(s))
}
