package backends

// WatchOptions represents options for watch operations
type WatchOptions struct {
	WaitIndex uint64
	Keys      []string
}

// WatchOption configures the WatchPrefix operation
type WatchOption func(*WatchOptions)

// WithKeys reduces the scope of keys that can trigger updates to keys (not an exact match)
func WithKeys(keys []string) WatchOption {
	return func(o *WatchOptions) {
		o.Keys = keys
	}
}

// WithWaitIndex sets the WaitIndex of the watcher
func WithWaitIndex(waitIndex uint64) WatchOption {
	return func(o *WatchOptions) {
		o.WaitIndex = waitIndex
	}
}
