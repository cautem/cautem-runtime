package idp_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cautem/quarshell-runtime/idp"
)

func TestOIDCValidateRS256(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString([]byte{0x01, 0x00, 0x01})

	var issuer string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 issuer,
			"jwks_uri":               issuer + "/jwks",
			"authorization_endpoint": issuer + "/auth",
			"token_endpoint":         issuer + "/token",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{
				"kty": "RSA", "kid": "k1", "alg": "RS256", "use": "sig", "n": n, "e": e,
			}},
		})
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	issuer = ts.URL

	tok := mustSignJWT(t, key, map[string]any{
		"iss": issuer,
		"sub": "user-1",
		"aud": "cautem",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})

	v, err := idp.NewOIDC(idp.OIDCConfig{
		Issuer:            issuer,
		Audience:          "cautem",
		AllowInsecureHTTP: true,
		HTTPClient:        ts.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := v.Validate(context.Background(), tok)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "user-1" {
		t.Fatalf("sub=%q", claims.Subject)
	}
}

func TestOIDCValidateCompatJWKSAlgorithms(t *testing.T) {
	tests := []struct {
		name string
		alg  string
		key  func(t *testing.T) (map[string]any, func(string) []byte)
	}{
		{"PS256", "PS256", func(t *testing.T) (map[string]any, func(string) []byte) {
			private, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatal(err)
			}
			jwk := map[string]any{"kty": "RSA", "kid": "k1", "alg": "PS256", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(private.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1})}
			return jwk, func(input string) []byte {
				digest := sha256.Sum256([]byte(input))
				sig, err := rsa.SignPSS(rand.Reader, private, crypto.SHA256, digest[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
				if err != nil {
					t.Fatal(err)
				}
				return sig
			}
		}},
		{"ES256", "ES256", func(t *testing.T) (map[string]any, func(string) []byte) {
			private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			width := 32
			jwk := map[string]any{"kty": "EC", "kid": "k1", "alg": "ES256", "use": "sig", "crv": "P-256", "x": base64.RawURLEncoding.EncodeToString(private.X.FillBytes(make([]byte, width))), "y": base64.RawURLEncoding.EncodeToString(private.Y.FillBytes(make([]byte, width)))}
			return jwk, func(input string) []byte {
				digest := sha256.Sum256([]byte(input))
				r, s, err := ecdsa.Sign(rand.Reader, private, digest[:])
				if err != nil {
					t.Fatal(err)
				}
				sig := make([]byte, width*2)
				r.FillBytes(sig[:width])
				s.FillBytes(sig[width:])
				return sig
			}
		}},
		{"ES384", "ES384", func(t *testing.T) (map[string]any, func(string) []byte) {
			private, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			width := 48
			jwk := map[string]any{"kty": "EC", "kid": "k1", "alg": "ES384", "use": "sig", "crv": "P-384", "x": base64.RawURLEncoding.EncodeToString(private.X.FillBytes(make([]byte, width))), "y": base64.RawURLEncoding.EncodeToString(private.Y.FillBytes(make([]byte, width)))}
			return jwk, func(input string) []byte {
				digest := sha512.Sum384([]byte(input))
				r, s, err := ecdsa.Sign(rand.Reader, private, digest[:])
				if err != nil {
					t.Fatal(err)
				}
				sig := make([]byte, width*2)
				r.FillBytes(sig[:width])
				s.FillBytes(sig[width:])
				return sig
			}
		}},
		{"EdDSA", "EdDSA", func(t *testing.T) (map[string]any, func(string) []byte) {
			public, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			jwk := map[string]any{"kty": "OKP", "kid": "k1", "alg": "EdDSA", "use": "sig", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(public)}
			return jwk, func(input string) []byte { return ed25519.Sign(private, []byte(input)) }
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			jwk, sign := test.key(t)
			var issuer string
			mux := http.NewServeMux()
			mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "jwks_uri": issuer + "/jwks"})
			})
			mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{jwk}})
			})
			server := httptest.NewServer(mux)
			defer server.Close()
			issuer = server.URL
			claims, _ := json.Marshal(map[string]any{"iss": issuer, "sub": "oidc-user", "aud": "openshell-cli", "exp": time.Now().Add(time.Hour).Unix()})
			input := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"`+test.alg+`","typ":"JWT","kid":"k1"}`)) + "." + base64.RawURLEncoding.EncodeToString(claims)
			token := input + "." + base64.RawURLEncoding.EncodeToString(sign(input))
			validator, err := idp.NewOIDC(idp.OIDCConfig{Issuer: issuer, Audience: "openshell-cli", AllowInsecureHTTP: true, HTTPClient: server.Client()})
			if err != nil {
				t.Fatal(err)
			}
			identity, err := validator.Validate(context.Background(), token)
			if err != nil {
				t.Fatal(err)
			}
			if identity.Subject != "oidc-user" {
				t.Fatalf("subject=%q", identity.Subject)
			}
		})
	}
}

func mustSignJWT(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT","kid":"k1"}`))
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	pl := base64.RawURLEncoding.EncodeToString(payload)
	input := hdr + "." + pl
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}
