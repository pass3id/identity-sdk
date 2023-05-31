package oi4vp

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v3"
)

type StaticKeySet struct {
	PublicKeys []crypto.PublicKey
}

func (s *StaticKeySet) VerifySignature(ctx context.Context, jwt string) ([]byte, error) {
	jws, err := jose.ParseSigned(jwt)
	if err != nil {
		return nil, fmt.Errorf("parsing jwt: %v", err)
	}
	for _, pub := range s.PublicKeys {
		switch pub.(type) {
		case *rsa.PublicKey:
		case *ecdsa.PublicKey:
		case ed25519.PublicKey:
		default:
			return nil, fmt.Errorf("invalid public key type provided: %T", pub)
		}
		payload, err := jws.Verify(pub)
		if err != nil {
			continue
		}
		return payload, nil
	}
	return nil, fmt.Errorf("no public keys able to verify jwt")
}

// get jwks from remote
func NewRemoteKeySet(ctx context.Context, jwksURL string) *RemoteKeySet {
	return &RemoteKeySet{jwksURL: jwksURL, ctx: ctx, now: time.Now}
}

type RemoteKeySet struct {
	jwksURL    string
	ctx        context.Context
	now        func() time.Time
	mu         sync.RWMutex
	cachedKeys []jose.JSONWebKey
}

var parsedJWTKey contextKey

// validates a payload against a signature from the jwks_uri.
func (r *RemoteKeySet) VerifySignature(ctx context.Context, jwt string) ([]byte, error) {
	jws, ok := ctx.Value(parsedJWTKey).(*jose.JSONWebSignature)
	if !ok {
		var err error
		jws, err = jose.ParseSigned(jwt)
		if err != nil {
			return nil, fmt.Errorf("oidc: malformed jwt: %v", err)
		}
	}
	return r.verify(ctx, jws)
}

// check from cache first, if not found, fetch from remote
func (r *RemoteKeySet) verify(ctx context.Context, jws *jose.JSONWebSignature) ([]byte, error) {
	keyID := ""
	for _, sig := range jws.Signatures {
		keyID = sig.Header.KeyID
		break
	}

	keys := r.keysFromCache()
	for _, key := range keys {
		if keyID == "" || key.KeyID == keyID {
			if payload, err := jws.Verify(&key); err == nil {
				return payload, nil
			}
		}
	}

	keys, err := r.keysFromRemote(ctx)
	if err != nil {
		return nil, fmt.Errorf("oi4vp: fetching keys %v", err)
	}

	for _, key := range keys {
		if keyID == "" || key.KeyID == keyID {
			if payload, err := jws.Verify(&key); err == nil {
				return payload, nil
			}
		}
	}
	return nil, errors.New("oi4vp: failed to verify id token signature")
}

func (r *RemoteKeySet) keysFromCache() (keys []jose.JSONWebKey) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cachedKeys
}

// set from the remote set, records the values in the
// cache, and returns the key set.
func (r *RemoteKeySet) keysFromRemote(ctx context.Context) ([]jose.JSONWebKey, error) {
	r.mu.Lock()
	keys, err := r.updateKeys()
	if err == nil {
		r.cachedKeys = keys
	}

	r.mu.Unlock()

	return keys, err
}

func (r *RemoteKeySet) updateKeys() ([]jose.JSONWebKey, error) {
	req, err := http.NewRequest("GET", r.jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("oi4vp: can't create request: %v", err)
	}

	resp, err := doRequest(r.ctx, req)
	if err != nil {
		return nil, fmt.Errorf("oi4vp: get keys failed %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("oi4vp: unable to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oi4vp: get keys failed: %s %s", resp.Status, body)
	}

	var keySet jose.JSONWebKeySet
	err = unmarshalResp(resp, body, &keySet)
	if err != nil {
		return nil, fmt.Errorf("oi4vp: failed to decode keys: %v %s", err, body)
	}
	return keySet.Keys, nil
}
