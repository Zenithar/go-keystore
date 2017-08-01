package key

import (
	"encoding/json"

	"github.com/mitchellh/mapstructure"
)

// FromString builds a Key instance from a map object
func FromString(input []byte) (Key, error) {
	var result rawJWK
	err := json.Unmarshal(input, &result)
	if err != nil {
		return nil, err
	}

	return fromRaw(&result)
}

// FromMap builds a Key instance from a map object
func FromMap(input map[string]interface{}) (Key, error) {
	var result rawJWK
	err := mapstructure.Decode(input, &result)
	if err != nil {
		return nil, err
	}

	return fromRaw(&result)
}

// fromRaw returns a concrete instance from the rawJWK specification
func fromRaw(raw *rawJWK) (Key, error) {
	switch raw.Algorithm {
	case "EC":
		switch raw.Curve {
		case "Ed25519":
			return toEd25519(raw)
		}
	default:
	}

	return nil, ErrAlgorithmNotSupported
}
