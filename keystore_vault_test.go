package keystore

import (
	"os"
	"testing"
	"time"

	. "github.com/onsi/gomega"

	"go.zenithar.org/keystore/key"
)

func TestVaultKeystore(t *testing.T) {
	RegisterTestingT(t)

	os.Setenv("VAULT_TOKEN", "b03559f2-62e2-2136-9d51-79e4e97d7788")

	ks, err := NewVault(key.Ed25519, "tokenizr")
	Expect(err).To(BeNil(), "Error should be nil on construction")
	Expect(ks).ToNot(BeNil(), "Keystore should not be nil on construction")

	k, err := ks.Generate()
	Expect(err).To(BeNil(), "Error should be nil on construction")
	Expect(k).ToNot(BeNil(), "Key should not be nil")

	ks.AddWithExpiration(k, 24*time.Hour)

	keys, err := ks.All()
	Expect(err).To(BeNil(), "Error should be nil on construction")
	Expect(keys).ToNot(BeNil(), "Keys collection should not be nil")
	Expect(len(keys)).To(Equal(1), "Keys collection count should be equal to 1")

	kl, err := ks.OnlyPublicKeys()
	Expect(err).To(BeNil(), "Error should be nil on construction")
	Expect(kl).ToNot(BeNil(), "Public Keys collection should not be nil")

	err = ks.Remove(k.ID())
	Expect(err).To(BeNil(), "Error should be nil on construction")
}
