package keystore

import "errors"

var (
	// ErrNotImplemented is raised when calling not implemented method
	ErrNotImplemented = errors.New("keystore: Method not implemented")
	// ErrKeyNotFound is raised when trying to get inexistant key from keystore
	ErrKeyNotFound = errors.New("keystore: Key not found")
	// ErrGeneratorNeedPositiveValueAboveOne is raised when caller gives a value under 1 as count
	ErrGeneratorNeedPositiveValueAboveOne = errors.New("keystore: Key generation count needs positive above 1 value as count")
)
