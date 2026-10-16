package secrets_test

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cautem/quarshell-runtime/secrets"
)

func TestInspectPinnedEnv(t *testing.T) {
	dir := t.TempDir()
	st := secrets.Inspect(dir, func(k string) string {
		if k == secrets.EnvKEK {
			return "test-passphrase-material"
		}
		return ""
	})
	if st.Source != secrets.SourceEnv || !st.Pinned {
		t.Fatalf("got %+v", st)
	}
	if w := st.Warning(); w != "" {
		t.Fatalf("unexpected warning: %s", w)
	}
}

func TestInspectFileVsNone(t *testing.T) {
	dir := t.TempDir()
	st := secrets.Inspect(dir, func(string) string { return "" })
	if st.Source != secrets.SourceNone {
		t.Fatalf("expected none, got %+v", st)
	}
	if st.Warning() == "" {
		t.Fatal("expected warning when none")
	}

	path := filepath.Join(dir, secrets.FileKEK)
	if err := os.WriteFile(path, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	st = secrets.Inspect(dir, func(string) string { return "" })
	if st.Source != secrets.SourceFile || st.Pinned {
		t.Fatalf("got %+v", st)
	}
	if st.Warning() == "" {
		t.Fatal("expected warning for file-backed KEK")
	}
}

func TestParseEnvKEKFormats(t *testing.T) {
	a, err := secrets.ParseEnvKEK("plain-passphrase")
	if err != nil || len(a) != 32 {
		t.Fatalf("plain: %v len=%d", err, len(a))
	}
	raw := make([]byte, 24)
	for i := range raw {
		raw[i] = byte(i + 1)
	}
	b64 := base64.StdEncoding.EncodeToString(raw)
	b, err := secrets.ParseEnvKEK(b64)
	if err != nil || len(b) != 32 {
		t.Fatalf("b64: %v", err)
	}
	// Same material → same derived key.
	b2, _ := secrets.ParseEnvKEK(b64)
	if string(b) != string(b2) {
		t.Fatal("derived keys differ")
	}
}

func TestPinnedKEKSurvivesEmptyDirRecreate(t *testing.T) {
	// Simulates compose recreate with CAUTEM_SECRETS_KEK set and a fresh data dir
	// that still must decrypt values written under the same KEK elsewhere —
	// here: same env across two dirs proves key identity.
	t.Setenv(secrets.EnvKEK, "prod-pinned-kek-material")
	dir1 := t.TempDir()
	s1, err := secrets.OpenLocal(dir1)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := s1.Put(ctx, secrets.ProviderKey("gh", "GITHUB_TOKEN"), "ghp_secret"); err != nil {
		t.Fatal(err)
	}

	dir2 := t.TempDir()
	// Copy ciphertext store into "new" volume; KEK from env must decrypt.
	src, err := os.ReadFile(filepath.Join(dir1, secrets.FileStore))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir2, secrets.FileStore), src, 0o600); err != nil {
		t.Fatal(err)
	}
	s2, err := secrets.OpenLocal(dir2)
	if err != nil {
		t.Fatal(err)
	}
	v, err := s2.Get(ctx, secrets.ProviderKey("gh", "GITHUB_TOKEN"))
	if err != nil || v != "ghp_secret" {
		t.Fatalf("recreate decrypt: %q %v", v, err)
	}
	st := secrets.Inspect(dir2, os.Getenv)
	if !st.Pinned || st.Source != secrets.SourceEnv {
		t.Fatalf("status %+v", st)
	}
}

func TestFileKEKSurvivesSameVolume(t *testing.T) {
	t.Setenv(secrets.EnvKEK, "") // ensure unset
	_ = os.Unsetenv(secrets.EnvKEK)
	dir := t.TempDir()
	s1, err := secrets.OpenLocal(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := s1.Put(ctx, "k", "v1"); err != nil {
		t.Fatal(err)
	}
	s2, err := secrets.OpenLocal(dir)
	if err != nil {
		t.Fatal(err)
	}
	v, err := s2.Get(ctx, "k")
	if err != nil || v != "v1" {
		t.Fatalf("got %q %v", v, err)
	}
	if secrets.Inspect(dir, func(string) string { return "" }).Source != secrets.SourceFile {
		t.Fatal("expected file source")
	}
}

func TestOpenLocalRejectsSymlinkKEK(t *testing.T) {
	t.Setenv(secrets.EnvKEK, "")
	dir := t.TempDir()
	target := filepath.Join(dir, "key-material")
	if err := os.WriteFile(target, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, secrets.FileKEK)); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	if _, err := secrets.OpenLocal(dir); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("OpenLocal error = %v, want symlink rejection", err)
	}
}

func TestOpenLocalTightensKEKAndDirectoryPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows filesystem permissions do not expose POSIX mode bits")
	}
	t.Setenv(secrets.EnvKEK, "")
	dir := filepath.Join(t.TempDir(), "secrets")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, secrets.FileKEK)
	if err := os.WriteFile(keyPath, make([]byte, 32), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := secrets.OpenLocal(dir); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]os.FileMode{dir: 0o700, keyPath: 0o600} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != want {
			t.Errorf("%s mode = %04o, want %04o", path, got, want)
		}
	}
}
