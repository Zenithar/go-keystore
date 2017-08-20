package key

import "context"

// Generator is the key builder to use for the keystore
type Generator func(context.Context) (Key, error)
