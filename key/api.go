package key

// Generator is the key builder to use for the keystore
type Generator func() (Key, error)
