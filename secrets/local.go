// Package secrets — LocalEncrypted persists provider credential values next to
// gateway state (OpenShell-like: values never appear in state.json plaintext).
package secrets

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/crypto/scrypt"
)

// LocalEncrypted is an AES-GCM file-backed Store keyed by logical names
// (typically "provider/<name>/<ENV_KEY>").
type LocalEncrypted struct {
	mu   sync.Mutex
	dir  string
	aead cipher.AEAD
	salt string            // base64 salt for a password-derived v2 KEK
	data map[string]string // plaintext cache; disk holds ciphertext only
}

type diskBlob struct {
	Version int               `json:"version"`
	Salt    string            `json:"salt,omitempty"`
	Entries map[string]string `json:"entries"` // key → base64(nonce|ciphertext)
}

// OpenLocal opens or creates an encrypted store under dir.
// KEK comes from CAUTEM_SECRETS_KEK (raw, hex, or base64) or a generated secrets.kek file.
func OpenLocal(dir string) (*LocalEncrypted, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("secrets: secure data directory: %w", err)
	}
	var existing diskBlob
	if raw, err := os.ReadFile(filepath.Join(dir, FileStore)); err == nil {
		if err := json.Unmarshal(raw, &existing); err != nil {
			return nil, fmt.Errorf("secrets: parse: %w", err)
		}
		if existing.Version != 1 && existing.Version != 2 {
			return nil, fmt.Errorf("secrets: unsupported store version %d", existing.Version)
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	legacy := existing.Version == 1
	kek, salt, err := resolveKEK(dir, os.Getenv, existing, legacy, false)
	if err != nil {
		return nil, err
	}
	aead, err := newAEAD(kek)
	if err != nil {
		return nil, err
	}
	s := &LocalEncrypted{
		dir:  dir,
		aead: aead,
		salt: salt,
		data: map[string]string{},
	}
	if err := s.loadLocked(); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if legacy {
		// The old ciphertext stays intact until the new file is synced and renamed.
		newKey, newSalt, err := resolveKEK(dir, os.Getenv, diskBlob{}, false, true)
		if err != nil {
			return nil, err
		}
		newCipher, err := newAEAD(newKey)
		if err != nil {
			return nil, err
		}
		s.aead, s.salt = newCipher, newSalt
		if err := s.flushLocked(); err != nil {
			return nil, fmt.Errorf("secrets: migrate legacy store: %w", err)
		}
	}
	return s, nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func resolveKEK(dir string, getenv func(string) string, blob diskBlob, legacy, migration bool) ([]byte, string, error) {
	v := strings.TrimSpace(getenv(EnvKEK))
	if v == "" {
		key, err := loadOrCreateKEK(dir, func(string) string { return "" })
		return key, "", err
	}
	if legacy {
		key, err := ParseEnvKEK(v)
		return key, "", err
	}
	if raw, ok := decodeRawKEK(v); ok {
		if blob.Salt != "" {
			return nil, "", fmt.Errorf("secrets: store needs password-derived KEK")
		}
		return raw, "", nil
	}
	if len(v) < 16 && !migration && blob.Version == 0 {
		return nil, "", fmt.Errorf("secrets: %s password must be at least 16 characters", EnvKEK)
	}
	salt := blob.Salt
	if salt == "" && blob.Version == 2 {
		return nil, "", fmt.Errorf("secrets: store needs raw 32-byte KEK")
	}
	if salt == "" {
		b := make([]byte, 16)
		if _, err := io.ReadFull(rand.Reader, b); err != nil {
			return nil, "", err
		}
		salt = base64.StdEncoding.EncodeToString(b)
	}
	b, err := base64.StdEncoding.DecodeString(salt)
	if err != nil || len(b) != 16 {
		return nil, "", fmt.Errorf("secrets: invalid KEK salt")
	}
	key, err := scrypt.Key([]byte(v), b, 1<<15, 8, 1, kekBytes)
	return key, salt, err
}

// loadOrCreateKEK resolves the KEK using Inspect order: env → file → generate file.
func loadOrCreateKEK(dir string, getenv func(string) string) ([]byte, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	if v := strings.TrimSpace(getenv(EnvKEK)); v != "" {
		return ParseEnvKEK(v)
	}
	path := filepath.Join(dir, FileKEK)
	if b, err := readExistingKEK(path); err == nil {
		return b, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	b := make([]byte, kekBytes)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return nil, err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	if err := syncDirectory(dir); err != nil {
		return nil, err
	}
	return b, nil
}

// readExistingKEK opens and validates the existing key without accepting a
// symlink or a non-regular file. Chmod is applied to the opened file so a path
// replacement cannot redirect the permission change to another file.
func readExistingKEK(path string) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("secrets: %s must not be a symlink", FileKEK)
	}
	if !before.Mode().IsRegular() {
		return nil, fmt.Errorf("secrets: %s must be a regular file", FileKEK)
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	opened, err := f.Stat()
	if err != nil {
		return nil, err
	}
	current, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if current.Mode()&os.ModeSymlink != 0 || !os.SameFile(before, opened) || !os.SameFile(opened, current) {
		return nil, fmt.Errorf("secrets: %s changed while opening", FileKEK)
	}
	if !opened.Mode().IsRegular() {
		return nil, fmt.Errorf("secrets: %s must be a regular file", FileKEK)
	}
	if err := f.Chmod(0o600); err != nil {
		return nil, fmt.Errorf("secrets: secure %s: %w", FileKEK, err)
	}

	b, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	if len(b) != kekBytes {
		return nil, fmt.Errorf("secrets: invalid %s length", FileKEK)
	}
	return b, nil
}

func (s *LocalEncrypted) loadLocked() error {
	path := filepath.Join(s.dir, FileStore)
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var blob diskBlob
	if err := json.Unmarshal(raw, &blob); err != nil {
		return fmt.Errorf("secrets: parse: %w", err)
	}
	out := map[string]string{}
	for k, enc := range blob.Entries {
		pt, err := s.decrypt(enc)
		if err != nil {
			return fmt.Errorf("secrets: decrypt %s: %w", k, err)
		}
		out[k] = pt
	}
	s.data = out
	return nil
}

func (s *LocalEncrypted) flushLocked() error {
	_, err := s.flushDataLocked(s.data)
	return err
}

// flushDataLocked reports whether the rename committed the new store. A
// directory-sync error after rename is returned to the caller, but the new
// file is already visible and must be reflected in the in-memory cache.
func (s *LocalEncrypted) flushDataLocked(data map[string]string) (bool, error) {
	blob := diskBlob{Version: 2, Salt: s.salt, Entries: map[string]string{}}
	for k, v := range data {
		enc, err := s.encrypt(v)
		if err != nil {
			return false, err
		}
		blob.Entries[k] = enc
	}
	raw, err := json.MarshalIndent(blob, "", "  ")
	if err != nil {
		return false, err
	}
	path := filepath.Join(s.dir, FileStore)
	f, err := os.CreateTemp(s.dir, ".secrets-*.tmp")
	if err != nil {
		return false, err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return false, err
	}
	if _, err := f.Write(raw); err != nil {
		f.Close()
		return false, err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return false, err
	}
	if err := f.Close(); err != nil {
		return false, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return false, err
	}
	if err := syncDirectory(s.dir); err != nil {
		return true, err
	}
	return true, nil
}

func (s *LocalEncrypted) commitLocked(next map[string]string) error {
	committed, err := s.flushDataLocked(next)
	if committed {
		s.data = next
	}
	return err
}

func cloneSecrets(data map[string]string) map[string]string {
	clone := make(map[string]string, len(data))
	for k, v := range data {
		clone[k] = v
	}
	return clone
}

func (s *LocalEncrypted) encrypt(plain string) (string, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ct := s.aead.Seal(nonce, nonce, []byte(plain), nil)
	return base64.StdEncoding.EncodeToString(ct), nil
}

func (s *LocalEncrypted) decrypt(enc string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return "", err
	}
	ns := s.aead.NonceSize()
	if len(raw) < ns {
		return "", fmt.Errorf("ciphertext too short")
	}
	pt, err := s.aead.Open(nil, raw[:ns], raw[ns:], nil)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// Get implements Store.
func (s *LocalEncrypted) Get(_ context.Context, key string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key = strings.TrimSpace(key)
	if key == "" {
		return "", fmt.Errorf("secrets: empty key")
	}
	v, ok := s.data[key]
	if !ok {
		return "", ErrNotFound{Key: key}
	}
	return v, nil
}

// Put stores a plaintext value under key.
func (s *LocalEncrypted) Put(_ context.Context, key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key = strings.TrimSpace(key)
	if key == "" {
		return fmt.Errorf("secrets: empty key")
	}
	if value == "" {
		return fmt.Errorf("secrets: empty value for %q", key)
	}
	next := cloneSecrets(s.data)
	next[key] = value
	return s.commitLocked(next)
}

// Delete removes a key.
func (s *LocalEncrypted) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneSecrets(s.data)
	delete(next, key)
	return s.commitLocked(next)
}

// DeletePrefix removes all keys with the given prefix.
func (s *LocalEncrypted) DeletePrefix(_ context.Context, prefix string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneSecrets(s.data)
	for k := range next {
		if strings.HasPrefix(k, prefix) {
			delete(next, k)
		}
	}
	return s.commitLocked(next)
}

// ProviderKey builds the canonical store key for a provider credential.
func ProviderKey(providerName, envKey string) string {
	return "provider/" + providerName + "/" + envKey
}

// PutProviderCredentials writes all credential values for a provider instance.
func (s *LocalEncrypted) PutProviderCredentials(_ context.Context, providerName string, creds map[string]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := false
	var next map[string]string
	for k, v := range creds {
		k = strings.TrimSpace(k)
		if k == "" || strings.TrimSpace(v) == "" {
			continue
		}
		if next == nil {
			next = cloneSecrets(s.data)
		}
		next[ProviderKey(providerName, k)] = v
		changed = true
	}
	if changed {
		return s.commitLocked(next)
	}
	return nil
}

// GetProviderCredentials returns env KEY→value for the listed env keys.
// Missing keys are skipped (not an error).
func (s *LocalEncrypted) GetProviderCredentials(ctx context.Context, providerName string, envKeys []string) (map[string]string, error) {
	out := map[string]string{}
	for _, k := range envKeys {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		v, err := s.Get(ctx, ProviderKey(providerName, k))
		if err != nil {
			continue
		}
		if v != "" {
			out[k] = v
		}
	}
	return out, nil
}
