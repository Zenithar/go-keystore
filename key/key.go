package key

import "errors"

// Key contract for key information holder
type Key interface {
	ID() string
	Algorithm() string
	HasPrivate() bool
	HasPublic() bool
	Public() Key
	Sign([]byte) ([]byte, error)
	Verify([]byte, []byte) (bool, error)
}

// -----------------------------------------------------------------------------

var (
	ErrInvalidSignature                            = errors.New("key: invalid signature")
	ErrInvalidOperationCouldSignWithoutPrivateKey  = errors.New("key: invalid operation : could not sign without a private key")
	ErrInvalidOperationCouldVerifyWithoutPublicKey = errors.New("key: invalid operation : could not verify without a public key")
	ErrAlgorithmNotSupported                       = errors.New("key: Algorithm not supported")
)
