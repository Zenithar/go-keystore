package key

import (
	"encoding/base64"

	"golang.org/x/crypto/sha3"
)

func keyIDFromData(data []byte) string {
	hasher := sha3.New256()
	hasher.Write(data)
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(hasher.Sum(nil))
}
