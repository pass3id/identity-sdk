package oi4vp

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

const (
	P3AccessToken = "eyJhbGciOiJFUzI1NiIsImtpZCI6ImFESmg0enZiZzNzRjFTWjRuYXJlVUxxTmVhSW5LeGluVUhQZHpGYjNYMmcifQ.eyJhenAiOiJLQXAwMmRncnJlZHciLCJkaWQiOiJkaWQ6ZXRocjoweEFEMTExQjIyMUUyMTVERDdENTk0NTMwODhGMzRjMTBmMzUzQWRiOWIiLCJleHAiOjE2ODQ0ODA1NzMsImlhdCI6MTY4NDQ3OTM3MywiaXNzIjoiUEFTUzMgVGVzdCIsImp0aSI6IktTZTBnMDI4MDlnNjRybTJoZ3JyZWR3MDAwYXEwMncyajdhajA1Zmt0bmJienZwczAwNjFzazgiLCJyb2xlcyI6WyJSZWd1bGFyVXNlciJdLCJzdWIiOiJLVXMwYTAwMDViZzFlMTkzbjkiLCJ0ZXJtaW5hbF9pZCI6IktUeDA4MDFoNjUwbWM2NjNrZjAwMDJucjBxMG1odG1nMWJ3eW5hdHp5eHA4In0.ZJ4VyNoRmahAOcyQFjpilQazzqbI-Q79UOYcKl6bpaEJiKI65S19R-xR2Y4RB2AQG_EB4hm7VZyMj3SepDZ3uQ"
	P3SigningAlg  = ES256
)

func TestNewProvider(t *testing.T) {
	tests := []struct {
		name              string
		data              string
		issuerURLOverride string
		trailingSlash     bool
		wantAuthURL       string
		wantTokenURL      string
		wantUserInfoURL   string
		wantIssuerURL     string
		wantAlgorithms    []string
		wantErr           bool
	}{
		{
			name: "basic_case",
			data: `{
				"issuer": "ISSUER",
				"authorization_endpoint": "https://example.com/auth",
				"token_endpoint": "https://example.com/token",
				"jwks_uri": "https://example.com/keys",
				"id_token_signing_alg_values_supported": ["RS256"]
			}`,
			wantAuthURL:    "https://example.com/auth",
			wantTokenURL:   "https://example.com/token",
			wantAlgorithms: []string{"RS256"},
		},
		{
			name: "additional_algorithms",
			data: `{
				"issuer": "ISSUER",
				"authorization_endpoint": "https://example.com/auth",
				"token_endpoint": "https://example.com/token",
				"jwks_uri": "https://example.com/keys",
				"id_token_signing_alg_values_supported": ["RS256", "RS384", "ES256", "EdDSA"]
			}`,
			wantAuthURL:    "https://example.com/auth",
			wantTokenURL:   "https://example.com/token",
			wantAlgorithms: []string{"RS256", "RS384", "ES256", "EdDSA"},
		},
		{
			name: "unsupported_algorithms",
			data: `{
				"issuer": "ISSUER",
				"authorization_endpoint": "https://example.com/auth",
				"token_endpoint": "https://example.com/token",
				"jwks_uri": "https://example.com/keys",
				"id_token_signing_alg_values_supported": [
					"RS256", "RS384", "ES256", "HS256", "none"
				]
			}`,
			wantAuthURL:    "https://example.com/auth",
			wantTokenURL:   "https://example.com/token",
			wantAlgorithms: []string{"RS256", "RS384", "ES256"},
		},
		{
			name: "mismatched_issuer",
			data: `{
				"issuer": "https://example.com",
				"authorization_endpoint": "https://example.com/auth",
				"token_endpoint": "https://example.com/token",
				"jwks_uri": "https://example.com/keys",
				"id_token_signing_alg_values_supported": ["RS256"]
			}`,
			wantErr: true,
		},
		{
			name: "issuer_with_trailing_slash",
			data: `{
				"issuer": "ISSUER",
				"authorization_endpoint": "https://example.com/auth",
				"token_endpoint": "https://example.com/token",
				"jwks_uri": "https://example.com/keys",
				"id_token_signing_alg_values_supported": ["RS256"]
			}`,
			trailingSlash:  true,
			wantAuthURL:    "https://example.com/auth",
			wantTokenURL:   "https://example.com/token",
			wantAlgorithms: []string{"RS256"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			var issuer string
			hf := func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/.well-known/openid-configuration" {
					http.NotFound(w, r)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				io.WriteString(w, strings.ReplaceAll(test.data, "ISSUER", issuer))
			}
			s := httptest.NewServer(http.HandlerFunc(hf))
			defer s.Close()

			issuer = s.URL
			if test.trailingSlash {
				issuer += "/"
			}

			p, err := NewProvider(ctx, issuer)
			if err != nil {
				if !test.wantErr {
					t.Errorf("NewProvider() failed: %v", err)
				}
				return
			}
			if test.wantErr {
				t.Fatalf("NewProvider(): expected error")
			}

			if test.wantIssuerURL != "" && p.issuer != test.wantIssuerURL {
				t.Errorf("NewProvider() unexpected issuer value, got=%s, want=%s",
					p.issuer, test.wantIssuerURL)
			}

			if p.authURL != test.wantAuthURL {
				t.Errorf("NewProvider() unexpected authURL value, got=%s, want=%s",
					p.authURL, test.wantAuthURL)
			}
			if p.tokenURL != test.wantTokenURL {
				t.Errorf("NewProvider() unexpected tokenURL value, got=%s, want=%s",
					p.tokenURL, test.wantTokenURL)
			}
			if !reflect.DeepEqual(p.algorithms, test.wantAlgorithms) {
				t.Errorf("NewProvider() unexpected algorithms value, got=%s, want=%s",
					p.algorithms, test.wantAlgorithms)
			}
		})
	}
}

func TestGetClient(t *testing.T) {
	ctx := context.Background()
	if c := getClient(ctx); c != nil {
		t.Errorf("cloneContext(): expected no *http.Client from empty context")
	}

	c := &http.Client{}
	ctx = ClientContext(ctx, c)
	if got := getClient(ctx); got == nil || c != got {
		t.Errorf("cloneContext(): expected *http.Client from context")
	}
}
