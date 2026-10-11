package secrets

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLocalEncryptedRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenLocal(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := s.PutProviderCredentials(ctx, "cursor", map[string]string{"CURSOR_API_KEY": "crsr_test"}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetProviderCredentials(ctx, "cursor", []string{"CURSOR_API_KEY", "MISSING"})
	if err != nil {
		t.Fatal(err)
	}
	if got["CURSOR_API_KEY"] != "crsr_test" {
		t.Fatalf("got %#v", got)
	}
	if _, ok := got["MISSING"]; ok {
		t.Fatal("missing should be omitted")
	}
	s2, err := OpenLocal(dir)
	if err != nil {
		t.Fatal(err)
	}
	v, err := s2.Get(ctx, ProviderKey("cursor", "CURSOR_API_KEY"))
	if err != nil || v != "crsr_test" {
		t.Fatalf("reopen: %q %v", v, err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, FileStore))
	if strings.Contains(string(raw), "crsr_test") {
		t.Fatal("plaintext leaked into secrets.enc.json")
	}
}

func TestFailedMutationsKeepMemoryAndDiskUnchanged(t *testing.T) {
	t.Setenv(EnvKEK, "")
	ctx := context.Background()
	mutations := []struct {
		name        string
		apply       func(*LocalEncrypted) error
		newKey      string
		wantMissing bool
	}{
		{
			name: "put",
			apply: func(s *LocalEncrypted) error {
				return s.Put(ctx, "existing", "replacement")
			},
		},
		{
			name: "delete",
			apply: func(s *LocalEncrypted) error {
				return s.Delete(ctx, "existing")
			},
		},
		{
			name: "delete-prefix",
			apply: func(s *LocalEncrypted) error {
				return s.DeletePrefix(ctx, "exist")
			},
		},
		{
			name: "put-provider-credentials",
			apply: func(s *LocalEncrypted) error {
				return s.PutProviderCredentials(ctx, "test", map[string]string{"TOKEN": "new-token"})
			},
			newKey:      ProviderKey("test", "TOKEN"),
			wantMissing: true,
		},
	}

	for _, tc := range mutations {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			s, err := OpenLocal(dir)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Put(ctx, "existing", "original"); err != nil {
				t.Fatal(err)
			}

			storePath := filepath.Join(dir, FileStore)
			backupPath := filepath.Join(dir, "secrets.enc.json.backup")
			if err := os.Rename(storePath, backupPath); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(storePath, 0o700); err != nil {
				t.Fatal(err)
			}

			if err := tc.apply(s); err == nil {
				t.Fatal("mutation succeeded while the store path was a directory")
			}
			if got, err := s.Get(ctx, "existing"); err != nil || got != "original" {
				t.Fatalf("in-memory value after failed mutation = %q, %v; want original", got, err)
			}
			if tc.wantMissing {
				if _, err := s.Get(ctx, tc.newKey); err == nil {
					t.Fatalf("failed mutation left %q in memory", tc.newKey)
				}
			}

			if err := os.RemoveAll(storePath); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(backupPath, storePath); err != nil {
				t.Fatal(err)
			}
			reopened, err := OpenLocal(dir)
			if err != nil {
				t.Fatal(err)
			}
			if got, err := reopened.Get(ctx, "existing"); err != nil || got != "original" {
				t.Fatalf("persisted value after failed mutation = %q, %v; want original", got, err)
			}
		})
	}
}

func TestLegacyStoreMigratesAtomicallyToPasswordKDF(t *testing.T) {
	dir := t.TempDir()
	password := "legacy-short"
	t.Setenv(EnvKEK, password)
	block, err := aes.NewCipher(DeriveKEK([]byte(password)))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, aead.NonceSize())
	encoded := base64.StdEncoding.EncodeToString(aead.Seal(nonce, nonce, []byte("secret"), nil))
	legacy, err := json.Marshal(diskBlob{Version: 1, Entries: map[string]string{"key": encoded}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, FileStore)
	if err := os.WriteFile(path, legacy, 0600); err != nil {
		t.Fatal(err)
	}
	s, err := OpenLocal(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s.Get(context.Background(), "key"); err != nil || got != "secret" {
		t.Fatalf("migrated value: %q %v", got, err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var blob diskBlob
	if err := json.Unmarshal(raw, &blob); err != nil || blob.Version != 2 || blob.Salt == "" {
		t.Fatalf("expected salted v2 store: %+v, %v", blob, err)
	}
	if _, err := OpenLocal(dir); err != nil {
		t.Fatalf("reopen migrated store: %v", err)
	}
	t.Setenv(EnvKEK, "different-password-material")
	if _, err := OpenLocal(dir); err == nil {
		t.Fatal("wrong password unexpectedly decrypted migrated store")
	}
}

func TestFreshStoreRejectsShortPassword(t *testing.T) {
	t.Setenv(EnvKEK, "short")
	if _, err := OpenLocal(t.TempDir()); err == nil {
		t.Fatal("new store accepted short password")
	}
}
