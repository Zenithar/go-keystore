package keystore

import (
	"go.zenithar.org/keystore/backends"
	"go.zenithar.org/keystore/key"
)

// Options contains all values that are needed for keystore.
type Options struct {
	Generator key.Generator
	Backend   backends.Backend
	Interval  uint64
}

// Option configures the keystore.
type Option func(*Options)

// WithInterval sets the backend polling interval.
func WithInterval(interval uint64) Option {
	return func(o *Options) {
		o.Interval = interval
	}
}

// WithGenerator sets the keystore key generator
func WithGenerator(generator key.Generator) Option {
	return func(o *Options) {
		o.Generator = generator
	}
}

// WithBackend sets the backend implementation
func WithBackend(backend backends.Backend) Option {
	return func(o *Options) {
		o.Backend = backend
	}
}
