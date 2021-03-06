package keystore

import (
	"testing"

	. "github.com/onsi/gomega"

	"go.zenithar.org/keystore/key"
)

func TestInMemoryKeystore(t *testing.T) {
	RegisterTestingT(t)

	ks, err := NewInMemory(key.Ed25519)
	Expect(err).To(BeNil(), "Error should be nil on construction")
	Expect(ks).ToNot(BeNil(), "Keystore should not be nil on construction")

	k, err := ks.Generate()
	Expect(err).To(BeNil(), "Error should be nil on construction")
	Expect(k).ToNot(BeNil(), "Key should not be nil")

	ks.Add(k)

	keys, err := ks.All()
	Expect(err).To(BeNil(), "Error should be nil on construction")
	Expect(keys).ToNot(BeNil(), "Keys collection should not be nil")
	Expect(len(keys)).To(Equal(1), "Keys collection count should be equal to 1")

	kl, err := ks.OnlyPublicKeys()
	Expect(err).To(BeNil(), "Error should be nil on construction")
	Expect(kl).ToNot(BeNil(), "Public Keys collection should not be nil")
}
