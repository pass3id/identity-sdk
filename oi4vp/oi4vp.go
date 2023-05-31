package oi4vp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

type contextKey int

var issuerURLKey contextKey

func ClientContext(ctx context.Context, client *http.Client) context.Context {
	return context.WithValue(ctx, oauth2.HTTPClient, client)
}

func getClient(ctx context.Context) *http.Client {
	if c, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok {
		return c
	}
	return nil
}

func doRequest(ctx context.Context, req *http.Request) (*http.Response, error) {
	client := http.DefaultClient
	if c := getClient(ctx); c != nil {
		client = c
	}
	return client.Do(req.WithContext(ctx))
}

var supportedAlgorithms = map[string]bool{
	RS256: true,
	RS384: true,
	RS512: true,
	ES256: true,
	ES384: true,
	ES512: true,
	PS256: true,
	PS384: true,
	PS512: true,
	EdDSA: true,
}

type Provider struct {
	issuer      string
	authURL     string
	tokenURL    string
	userInfoURL string
	jwksURL     string
	algorithms  []string

	// Raw claims returned by the server.
	rawClaims []byte

	// Guards all of the following fields.
	mu sync.Mutex
	// HTTP client specified from the initial NewProvider request. This is used
	// when creating the common key set.
	client *http.Client
	// A key set that uses context.Background() and is shared between all code paths
	// that don't have a convinent way of supplying a unique context.
	commonRemoteKeySet KeySet
}

func (p *Provider) remoteKeySet() KeySet {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.commonRemoteKeySet == nil {
		ctx := context.Background()
		if p.client != nil {
			ctx = ClientContext(ctx, p.client)
		}
		p.commonRemoteKeySet = NewRemoteKeySet(ctx, p.jwksURL)
	}
	return p.commonRemoteKeySet
}

func (p *Provider) Endpoint() oauth2.Endpoint {
	return oauth2.Endpoint{AuthURL: p.authURL, TokenURL: p.tokenURL}
}

type ProviderConfig struct {
	IssuerURL   string
	AuthURL     string
	TokenURL    string
	UserInfoURL string
	JWKSURL     string
	Algorithms  []string
}

func (p *ProviderConfig) NewProvider(ctx context.Context) *Provider {
	return &Provider{
		issuer:      p.IssuerURL,
		authURL:     p.AuthURL,
		tokenURL:    p.TokenURL,
		userInfoURL: p.UserInfoURL,
		jwksURL:     p.JWKSURL,
		algorithms:  p.Algorithms,
		client:      getClient(ctx),
	}
}

// Optional provider initialization that get configuration
// from remote /.well-known/openid-configuration
func NewProvider(ctx context.Context, issuer string) (*Provider, error) {
	wellKnown := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequest("GET", wellKnown, nil)
	if err != nil {
		return nil, err
	}
	resp, err := doRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", resp.Status, body)
	}

	var p providerJSON
	err = unmarshalResp(resp, body, &p)
	if err != nil {
		return nil, fmt.Errorf("oi4vp: failed to decode provider discovery object: %v", err)
	}

	issuerURL, skipIssuerValidation := ctx.Value(issuerURLKey).(string)
	if !skipIssuerValidation {
		issuerURL = issuer
	}
	if p.Issuer != issuerURL && !skipIssuerValidation {
		return nil, fmt.Errorf("oi4vp: issuer did not match the issuer returned by provider, expected %q got %q", issuer, p.Issuer)
	}
	var algs []string
	for _, a := range p.Algorithms {
		if supportedAlgorithms[a] {
			algs = append(algs, a)
		}
	}
	return &Provider{
		issuer:      issuerURL,
		authURL:     p.AuthURL,
		tokenURL:    p.TokenURL,
		userInfoURL: p.UserInfoURL,
		jwksURL:     p.JWKSURL,
		algorithms:  algs,
		rawClaims:   body,
		client:      getClient(ctx),
	}, nil
}

type providerJSON struct {
	Issuer      string   `json:"issuer"`
	AuthURL     string   `json:"authorization_endpoint"`
	TokenURL    string   `json:"token_endpoint"`
	JWKSURL     string   `json:"jwks_uri"`
	UserInfoURL string   `json:"userinfo_endpoint"`
	Algorithms  []string `json:"id_token_signing_alg_values_supported"`
}

type Token struct {
	Issuer       string
	Audience     []string
	Subject      string
	ID           string
	Nonce        string
	NotBefore    *time.Time
	Expiry       time.Time
	IssuedAt     time.Time
	SigAlgorithm string
	claims       []byte
}

func (t *Token) BuildClaims(v interface{}) error {
	if t.claims == nil {
		return fmt.Errorf("oi4vp: no claims to unmarshal")
	}
	return json.Unmarshal(t.claims, v)
}

type genericToken struct {
	Issuer    string                 `json:"iss"`
	Audience  audience               `json:"aud"`
	Subject   string                 `json:"sub"`
	ID        string                 `json:"jti"`
	Nonce     string                 `json:"nonce"`
	NotBefore *jsonTime              `json:"nbf"`
	Expiry    jsonTime               `json:"exp"`
	IssuedAt  jsonTime               `json:"iat"`
	Claims    map[string]interface{} `json:"-"`
}

type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		*a = audience{s}
		return nil
	}
	var auds []string
	if err := json.Unmarshal(b, &auds); err != nil {
		return err
	}
	*a = auds
	return nil
}

type jsonTime time.Time

func (j *jsonTime) UnmarshalJSON(b []byte) error {
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	var unix int64

	if t, err := n.Int64(); err == nil {
		unix = t
	} else {
		f, err := n.Float64()
		if err != nil {
			return err
		}
		unix = int64(f)
	}
	*j = jsonTime(time.Unix(unix, 0))
	return nil
}

func unmarshalResp(r *http.Response, body []byte, v interface{}) error {
	err := json.Unmarshal(body, &v)
	if err == nil {
		return nil
	}
	ct := r.Header.Get("Content-Type")
	mediaType, _, parseErr := mime.ParseMediaType(ct)
	if parseErr == nil && mediaType == "application/json" {
		return fmt.Errorf("oi4vp: could not unmarshal as JSON: %v", err)
	}
	return fmt.Errorf("oi4vp: wrong content-type, got %q: %v", ct, err)
}
