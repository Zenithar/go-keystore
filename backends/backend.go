package backends

import (
	"context"
)

// Backend Key / Value store contract
type Backend interface {
	Get(ctx context.Context, key string) ([]byte, error)
	Set(ctx context.Context, key string, value []byte) error
	List(ctx context.Context, key string) ([]string, error)
	WatchPrefix(ctx context.Context, prefix string, opts ...WatchOption) (uint64, error)
	Close(ctx context.Context) error
}
