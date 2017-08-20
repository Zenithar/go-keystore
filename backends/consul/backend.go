package consul

import (
	"context"
	"fmt"
	"strings"

	"go.zenithar.org/keystore/backends"

	"github.com/hashicorp/consul/api"
)

type consulBackend struct {
	client *api.Client
	kv     *api.KV
	prefix string
}

// New initializes a consul backend instance
func New(nodes []string, opts ...Option) (backends.Backend, error) {
	// Parse options
	var options Options
	for _, o := range opts {
		o(&options)
	}

	// initializes a default configuration
	conf := api.DefaultConfig()

	// Apply given settings
	conf.Scheme = options.Scheme

	// Server nodes
	if len(nodes) > 0 {
		conf.Address = nodes[0]
	}

	// TLS Connection
	tlsConfig := api.TLSConfig{}
	if options.TLS.ClientCert != "" && options.TLS.ClientKey != "" {
		tlsConfig.CertFile = options.TLS.ClientCert
		tlsConfig.KeyFile = options.TLS.ClientKey
	}

	if options.TLS.ClientCaKeys != "" {
		tlsConfig.CAFile = options.TLS.ClientCaKeys
	}
	conf.TLSConfig = tlsConfig

	// initialize the consul client
	client, err := api.NewClient(conf)
	if err != nil {
		return nil, err
	}

	return &consulBackend{
		client: client,
		kv:     client.KV(),
		prefix: options.Prefix,
	}, nil
}

// -----------------------------------------------------------------------------
func (b *consulBackend) Name() string {
	return "consul"
}

func (b *consulBackend) Get(ctx context.Context, key string) ([]byte, error) {
	pair, _, err := b.kv.Get(fmt.Sprintf("%s%s", b.prefix, key), nil)
	if err != nil {
		return nil, err
	}
	if pair == nil {
		return nil, nil
	}
	return pair.Value, nil
}

func (b *consulBackend) Set(ctx context.Context, key string, value []byte) error {
	pair := &api.KVPair{
		Key:   fmt.Sprintf("%s%s", b.prefix, key),
		Value: value,
	}

	_, err := b.kv.Put(pair, nil)
	return err
}

func (b *consulBackend) List(ctx context.Context, key string) ([]string, error) {
	scan := fmt.Sprintf("%s%s", b.prefix, key)

	// The TrimPrefix call below will not work correctly if we have "//" at the
	// end. This can happen in cases where you are e.g. listing the root of a
	// prefix in a logical backend via "/" instead of ""
	if strings.HasSuffix(scan, "//") {
		scan = scan[:len(scan)-1]
	}

	out, _, err := b.kv.Keys(scan, "/", nil)
	for idx, val := range out {
		out[idx] = strings.TrimPrefix(val, scan)
	}

	return out, err
}

type watchResponse struct {
	waitIndex uint64
	err       error
}

func (b *consulBackend) WatchPrefix(ctx context.Context, prefix string, opts ...backends.WatchOption) (uint64, error) {
	var options backends.WatchOptions
	for _, o := range opts {
		o(&options)
	}

	respChan := make(chan watchResponse)
	go func() {
		opts := api.QueryOptions{
			WaitIndex: options.WaitIndex,
		}
		_, meta, err := b.kv.List(prefix, &opts)
		if err != nil {
			respChan <- watchResponse{options.WaitIndex, err}
			return
		}
		respChan <- watchResponse{meta.LastIndex, err}
	}()
	for {
		select {
		case <-ctx.Done():
			return options.WaitIndex, backends.ErrWatchCanceled
		case r := <-respChan:
			return r.waitIndex, r.err
		}
	}

}

func (b *consulBackend) Close(ctx context.Context) error {
	return nil
}
