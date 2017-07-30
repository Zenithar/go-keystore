package key

import (
	"fmt"
	"testing"

	prettyjson "github.com/hokaccha/go-prettyjson"
	. "github.com/onsi/gomega"
)

func TestEd25519_Generation(t *testing.T) {
	RegisterTestingT(t)

	key, _ := Ed25519()
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
		Algorithm: "EC",
		Curve:     "Ed25519",
		KeyID:     "WPBK:AOP4:PHSV:CXYB:HIVA:PJ2S:E43Z:4PF3:HFFI:AVMG:OGBN:6XK7",
		KeyType:   "OKP",
		X:         "KuCra6cYFp3C4FcR4Yr6lC2gojKpS3d7wkazdKD_Dm4",
		D:         "cYZz_frjJCOiB2Ou-IsxYUu9MbrZhX0YLghvFC05brQq4KtrpxgWncLgVxHhivqULaCiMqlLd3vCRrN0oP8Obg",
	})

	Expect(key).ToNot(BeNil())
	Expect(err).To(BeNil())

	s, _ := prettyjson.Marshal(key)
	fmt.Println(string(s))

	Expect(key.Algorithm()).To(Equal("Ed25519"))
	Expect(key.ID()).To(Equal("WPBK:AOP4:PHSV:CXYB:HIVA:PJ2S:E43Z:4PF3:HFFI:AVMG:OGBN:6XK7"))
	Expect(key.HasPrivate()).To(BeTrue())
	Expect(key.HasPublic()).To(BeTrue())
}
