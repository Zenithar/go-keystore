package key

// rawJWK implements the internal representation for serialzing/deserializing a JWK: RFC 7517 Section 4
type rawJWK struct {
	PublicKeyUse             string   `json:"use,omitempty"`      // JWK 4.2
	KeyType                  string   `json:"kty,omitempty"`      // JWK 4.1
	KeyID                    string   `json:"kid,omitempty"`      // JWK 4.5
	KeyOperations            string   `json:"key_ops,omitempty"`  // JWK 4.3
	Curve                    string   `json:"crv,omitempty"`      // RSA Curve JWA 6.2.1.1
	Algorithm                string   `json:"alg,omitempty"`      // JWK 4.4
	K                        string   `json:"k,omitempty"`        // Symmetric Key JWA 6.4.1
	X                        string   `json:"x,omitempty"`        // RSA X Coordindate JWA 6.2.1.2
	Y                        string   `json:"y,omitempty"`        // RSA Y Coordinate JWA 6.2.1.3
	N                        string   `json:"n,omitempty"`        // RSA Modulus, JWA 6.3.1.1
	E                        string   `json:"e,omitempty"`        // RSA Exponent JWA 6.3.1.2
	D                        string   `json:"d,omitempty"`        // RSA Private Exponent JWA 6.3.2.1, ECC Private Key JWA 6.2.2.1
	P                        string   `json:"p,omitempty"`        // RSA First Prime Factor JWA 6.3.2.2
	Q                        string   `json:"q,omitempty"`        // RSA Second Prime Factor JWA 6.3.2.3
	Dp                       string   `json:"dp,omitempty"`       // RSA First Factor CRT Exponent JWA 6.3.2.4
	Dq                       string   `json:"dq,omitempty"`       // RSA SEcond Factor CRT Exponent JWA 6.3.2.5
	Qi                       string   `json:"qi,omitempty"`       // RSA First CRT Coefficient JWA 6.3.2.6
	X509URL                  string   `json:"x5u,omitempty"`      // JWK 4.6
	X509CertChain            []string `json:"x5c,omitempty"`      // JWK 4.7
	X509Sha1Thumbprint       string   `json:"x5t,omitempty"`      // JWK 4.8
	X509CertSha256Thumbprint string   `json:"x5t#S256,omitempty"` // JWK 4.9
}
