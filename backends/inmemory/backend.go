package inmemory

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"go.zenithar.org/keystore/backends"
)

type inMemoryBackend struct {
	sync.RWMutex

	data map[string]string
}

// New initializes a inmem backend instance
func New() (backends.Backend, error) {
	return &inMemoryBackend{
		data: make(map[string]string),
	}, nil
}

// -----------------------------------------------------------------------------
func (b *inMemoryBackend) Name() string {
	return "in-memory"
}

func (b *inMemoryBackend) Get(ctx context.Context, key string) ([]byte, error) {
	b.RLock()
	defer b.RUnlock()

	if value, ok := b.data[key]; ok {
		return []byte(value), nil
	}

	return nil, fmt.Errorf("inmemory: Key not found")
}

func (b *inMemoryBackend) Set(ctx context.Context, key string, value []byte) error {
	b.Lock()
	defer b.Unlock()

	b.data[key] = string(value)
	return nil
}

func (b *inMemoryBackend) List(ctx context.Context, key string) ([]string, error) {
	b.RLock()
	defer b.RUnlock()

	var result []string

	for k := range b.data {
		result = append(result, strings.TrimPrefix(k, fmt.Sprintf("%s/", key)))
	}

	return result, nil
}

func (b *inMemoryBackend) WatchPrefix(ctx context.Context, prefix string, opts ...backends.WatchOption) (uint64, error) {
	return 0, backends.ErrWatchNotSupported
}

func (b *inMemoryBackend) Close(ctx context.Context) error {
	return nil
}
