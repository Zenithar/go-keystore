package keystore

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/davecgh/go-spew/spew"
	vault "github.com/hashicorp/vault/api"

	"go.zenithar.org/keystore/key"
)

type vaultKeyStore struct {
	prefix    string
	generator KeyGenerator
	client    *vault.Client
}

// NewVault returns a vault based keystore
func NewVault(generator KeyGenerator, prefix string) (KeyStore, error) {

	// Initialize Vault Client
	config := vault.DefaultConfig()
	addr := os.Getenv("VAULT_HOST")
	if len(addr) == 0 {
		addr = "http://127.0.0.1:8200"
	}
	config.Address = addr

	// Prepare client
	c, err := vault.NewClient(config)
	if err != nil {
		return nil, err
	}

	// Auth with token
	token := os.Getenv("VAULT_TOKEN")
	if len(token) == 0 {
		return nil, fmt.Errorf("keystore: Unable to initialize Vault keystore without token")
	}
	c.SetToken(token)

	// Return keystore instance
	return &vaultKeyStore{
		generator: generator,
		client:    c,
		prefix:    prefix,
	}, nil
}

// -----------------------------------------------------------------------------
func (ks *vaultKeyStore) Generate() (key.Key, error) {
	k, err := ks.generator()
	if err != nil {
		return nil, fmt.Errorf("keystore: Key generation error %v", err)
	}

	return k, nil
}

func (ks *vaultKeyStore) All() ([]key.Key, error) {
	var result []key.Key

	secret, err := ks.client.Logical().List(ks.getSecretPath("jwk"))
	if err != nil {
		return nil, err
	}

	// No secret
	if secret == nil || secret.Data == nil {
		return result, nil
	}

	// No keys attribute
	if _, ok := secret.Data["keys"]; !ok {
		return result, nil
	}

	if keys, ok := secret.Data["keys"].([]interface{}); ok {
		for _, kid := range keys {
			k, err := ks.Get(kid.(string))
			if err != nil {
				logrus.WithError(err).WithField("kid", kid).Warn("Unable to decode key")
				continue
			}
			result = append(result, k)
		}
	}

	return result, nil
}

func (ks *vaultKeyStore) OnlyPublicKeys() ([]key.Key, error) {
	var result []key.Key

	keys, err := ks.All()
	if err != nil {
		return nil, err
	}

	for _, i := range keys {
		result = append(result, i.Public())
	}

	return result, nil
}

func (ks *vaultKeyStore) Get(id string) (key.Key, error) {
	var res key.Key

	secret, err := ks.getSecret(fmt.Sprintf("jwk/%s", id))
	if err != nil {
		return nil, fmt.Errorf("vault: Failed to retrieve secret")
	}

	if value, ok := secret["value"].(string); ok {
		// Deserialize key
		k, err := key.FromString([]byte(value))
		if err != nil {
			return nil, fmt.Errorf("vault: Failed to decode secret")
		}

		res = k
	}

	return res, nil
}

func (ks *vaultKeyStore) Pick() (key.Key, error) {
	return nil, ErrNotImplemented
}

func (ks *vaultKeyStore) Add(k key.Key) error {
	// Marshal to json
	jwk, err := json.Marshal(k)
	if err != nil {
		return fmt.Errorf("vault: Unable to serialize key as JSON : %T:%v", err, err)
	}

	// Check if key already exists
	k2, _ := ks.Get(k.ID())
	if k2 != nil {
		return fmt.Errorf("vault: Unable to insert key, KID is already known")
	}

	// Store key in vault
	err = ks.writeSecret(fmt.Sprintf("jwk/%s", k.ID()), map[string]interface{}{
		"value": string(jwk),
		"iat":   time.Now().UTC().Unix(),
	})
	if err != nil {
		return fmt.Errorf("vault: Unable to add a key to the vault: %T:%v", err, err)
	}

	return nil
}

func (ks *vaultKeyStore) AddWithExpiration(k key.Key, exp time.Duration) error {
	// Marshal to json
	jwk, err := json.Marshal(k)
	if err != nil {
		return fmt.Errorf("vault: Unable to serialize key as JSON : %T:%v", err, err)
	}

	// Check if key already exists
	k2, _ := ks.Get(k.ID())
	if k2 != nil {
		return fmt.Errorf("vault: Unable to insert key, KID is already known")
	}

	// Store key in vault
	err = ks.writeSecret(fmt.Sprintf("jwk/%s", k.ID()), map[string]interface{}{
		"value": string(jwk),
		"iat":   time.Now().UTC().Unix(),
		"exp":   time.Now().UTC().Add(exp).Unix(),
	})
	if err != nil {
		return fmt.Errorf("vault: Unable to add a key to the vault: %T:%v", err, err)
	}

	return nil
}

func (ks *vaultKeyStore) Remove(id string) error {
	return ks.removeSecret(fmt.Sprintf("jwk/%s", id))
}

func (ks *vaultKeyStore) RotateKeys(ctx context.Context) error {
	return ks.rotateJob()
}

// -----------------------------------------------------------------------------

func (ks *vaultKeyStore) rotateJob() error {
	now := time.Now().UTC()

	// Retrieve last rotation date
	secret, _ := ks.getSecret("next_rotation")
	if secret != nil {
		// Parse date
		if dateRaw, ok := secret["value"]; ok {
			if nextRotation, ok := dateRaw.(json.Number); ok {
				v, _ := nextRotation.Int64()
				if time.Unix(v, 0).After(now) {
					// Rotation already done
					logrus.Debug("[VAULT] Key rotation already done, skipping ...")
					return nil
				}
			} else {
				return fmt.Errorf("vault: Unable to rotate keys, unable to decode next rotation date")
			}
		}
	}

	// Update rotation date
	err := ks.writeSecret("next_rotation", map[string]interface{}{
		"value": now.Add(5 * time.Minute).UTC().Unix(),
	})
	if err != nil {
		return fmt.Errorf("vault: Unable to rotate keys, unable to update rotation date: %T:%v", err, err)
	}

	// List all keys
	keys, err := ks.All()
	if err != nil {
		return fmt.Errorf("vault: Unable to rotate keys, unable to retrieve all keys: %T:%v", err, err)
	}

	// Ignore if no key available
	if len(keys) == 0 {
		logrus.Debug("[VAULT] No key to rotate, skipping ...")
		return nil
	}

	// For each key
	for _, k := range keys {
		secret, err := ks.getSecret(fmt.Sprintf("jwk/%s", k.ID()))
		if err != nil {
			logrus.WithError(err).WithField("kid", k.ID()).Warn("[VAULT] Unable to retrieve key from vault, skipping ...")
			continue
		}

		// Check expiration
		if expRaw, ok := secret["exp"]; ok {
			// Exp is a float64
			spew.Dump(expRaw)
			if expiration, ok := expRaw.(json.Number); ok {
				v, _ := expiration.Int64()

				// Calculate dates
				expirationDate := time.Unix(v, 0)
				deletionDate := expirationDate.Add(2 * time.Hour)

				// Check expiration time
				if now.After(expirationDate) {
					// Mark as unuseable
					secret["usable"] = false
					err = ks.writeSecret(fmt.Sprintf("jwk/%s", k.ID()), secret)
					if err != nil {
						logrus.WithError(err).WithField("kid", k.ID()).Warn("[VAULT] Unable to save key in vault, skipping ...")
						continue
					}
				}
				if now.After(deletionDate) {
					// Delete key after grace period
					err = ks.Remove(k.ID())
					if err != nil {
						logrus.WithError(err).WithField("kid", k.ID()).Warn("[VAULT] Unable to remove key from vault, skipping ...")
						continue
					}
				}
			} else {
				logrus.Error("vault: Expiration key type error.")
			}
		}
	}

	return nil
}

func (ks *vaultKeyStore) getSecret(path string) (map[string]interface{}, error) {
	secret, err := ks.client.Logical().Read(ks.getSecretPath(path))
	if err != nil || secret == nil {
		return nil, fmt.Errorf("vault: Failed to read secret")
	}
	return secret.Data, nil
}

func (ks *vaultKeyStore) getSecretPath(path string) string {
	return fmt.Sprintf("secret/%s/%s", ks.prefix, path)
}

func (ks *vaultKeyStore) writeSecret(path string, data map[string]interface{}) error {
	_, err := ks.client.Logical().Write(ks.getSecretPath(path), data)
	if err != nil {
		return fmt.Errorf("vault: Unable to write secret to the vault: %T:%v", err, err)
	}
	return nil
}

func (ks *vaultKeyStore) removeSecret(path string) error {
	_, err := ks.client.Logical().Delete(ks.getSecretPath(path))
	if err != nil {
		return fmt.Errorf("vault: Unable to remove secret from the vault: %T:%v", err, err)
	}
	return nil
}
