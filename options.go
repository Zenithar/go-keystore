package keystore

// Options contains all values that are needed for keystore.
type Options struct {
	OneTime  bool
	Watch    bool
	Interval uint64
	Snappy   bool
}

// Option configures the keystore.
type Option func(*Options)

// WithInterval sets the backend polling interval.
func WithInterval(interval uint64) Option {
	return func(o *Options) {
		o.Interval = interval
	}
}

// OneTime sets the backend polling interval.
func OneTime() Option {
	return func(o *Options) {
		o.OneTime = true
	}
}

// EnableWatch enables watch feature on backend side.
func EnableWatch() Option {
	return func(o *Options) {
		o.Watch = true
	}
}

// DisableSnappy compression for JWK data
func DisableSnappy() Option {
	return func(o *Options) {
		o.Snappy = false
	}
}
