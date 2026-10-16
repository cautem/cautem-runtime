package idp_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/cautem/quarshell-runtime/idp"
)

func TestPrepareAndExchangeAuthorizationCode(t *testing.T) {
	var issuer string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token",
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("code") != "code-1" || r.Form.Get("client_id") != "console" {
			t.Fatalf("unexpected token form: %v", r.Form)
		}
		if r.Form.Get("code_verifier") == "" {
			t.Fatal("code_verifier is empty")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access-1", "refresh_token": "refresh-1", "expires_in": 3600})
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	issuer = server.URL

	cfg := idp.PKCEConfig{Issuer: issuer, ClientID: "console", Audience: "cautem", Scopes: "profile openid", AllowInsecureHTTP: true, HTTPClient: server.Client()}
	prepared, err := idp.PrepareAuthorization(context.Background(), cfg, "http://127.0.0.1:8080/auth/callback")
	if err != nil {
		t.Fatal(err)
	}
	authorize, err := url.Parse(prepared.URL)
	if err != nil {
		t.Fatal(err)
	}
	query := authorize.Query()
	if query.Get("state") != prepared.State || query.Get("code_challenge_method") != "S256" || query.Get("audience") != "cautem" {
		t.Fatalf("unexpected authorization query: %v", query)
	}
	digest := sha256.Sum256([]byte(prepared.Verifier))
	if query.Get("code_challenge") != base64.RawURLEncoding.EncodeToString(digest[:]) {
		t.Fatal("PKCE challenge does not match verifier")
	}
	bundle, err := idp.ExchangeAuthorizationCode(context.Background(), cfg, prepared, "code-1")
	if err != nil {
		t.Fatal(err)
	}
	if bundle.AccessToken != "access-1" || bundle.RefreshToken != "refresh-1" || bundle.Expiry.IsZero() {
		t.Fatalf("unexpected token bundle: %+v", bundle)
	}
}

func TestPrepareAuthorizationRejectsInsecureIssuerAndRedirect(t *testing.T) {
	_, err := idp.PrepareAuthorization(context.Background(), idp.PKCEConfig{Issuer: "http://example.com", ClientID: "console"}, "https://console.example.com/auth/callback")
	if err == nil {
		t.Fatal("expected insecure issuer rejection")
	}
	_, err = idp.PrepareAuthorization(context.Background(), idp.PKCEConfig{Issuer: "https://issuer.example.com", ClientID: "console"}, "http://console.example.com/auth/callback")
	if err == nil {
		t.Fatal("expected insecure redirect rejection")
	}
}
