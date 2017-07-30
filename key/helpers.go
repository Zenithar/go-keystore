package key

import (
	"bytes"
	"encoding/base32"
	"strings"

	"golang.org/x/crypto/sha3"
)

// copied from docker/libtrust
func keyIDEncode(b []byte) string {
	s := strings.TrimRight(base32.StdEncoding.EncodeToString(b), "=")
	var buf bytes.Buffer
	var i int
	for i = 0; i < len(s)/4-1; i++ {
		start := i * 4
		end := start + 4
		buf.WriteString(s[start:end] + ":")
	}
	buf.WriteString(s[i*4:])
	return buf.String()
}

func keyIDFromData(data []byte) string {
	hasher := sha3.New256()
	hasher.Write(data)
	h := hasher.Sum(nil)[:30]
	return keyIDEncode(h)
}
