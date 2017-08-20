package consul

// Options contains all values that are needed to connect to consul.
type Options struct {
	Scheme string
	Prefix string
	TLS    TLSOptions
}

// TLSOptions contains all certificates and keys.
type TLSOptions struct {
	ClientCert   string
	ClientKey    string
	ClientCaKeys string
}

// Option configures the consul client.
type Option func(*Options)

// WithScheme sets the consul uri scheme.
func WithScheme(scheme string) Option {
	return func(o *Options) {
		o.Scheme = scheme
	}
}

// WithTLSOptions sets the TLSOptions.
func WithTLSOptions(tls TLSOptions) Option {
	return func(o *Options) {
		o.TLS = tls
	}
}

// WithPrefix sets the default key prefix
func WithPrefix(prefix string) Option {
	return func(o *Options) {
		o.Prefix = prefix
	}
}
