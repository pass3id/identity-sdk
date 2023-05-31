package oi4vp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	jose "github.com/go-jose/go-jose/v3"
	"golang.org/x/exp/slices"
	"golang.org/x/oauth2"
)

type TokenExpiredError struct {
	Expiry time.Time
}

func (e *TokenExpiredError) Error() string {
	return fmt.Sprintf("oi4vp: token is expired (Token Expiry: %v)", e.Expiry)
}

type KeySet interface {
	VerifySignature(ctx context.Context, jwt string) (payload []byte, err error)
}

type Config struct {
	ClientID                   string
	SupportedSigningAlgs       []string
	SkipClientIDCheck          bool
	SkipExpiryCheck            bool
	InsecureSkipSignatureCheck bool
	VPSignatureCheck           bool
	Now                        func() time.Time
}

func parseJWT(p string) ([]byte, error) {
	parts := strings.Split(p, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("oi4vp: malformed jwt, expected 3 parts got %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("oi4vp: malformed jwt payload: %v", err)
	}
	return payload, nil
}

func contains(sli []string, ele string) bool {
	for _, s := range sli {
		if s == ele {
			return true
		}
	}
	return false
}

type TokenVerifier struct {
	keySet KeySet
	config *Config
	issuer string
}

func NewVerifier(issuerURL string, keySet KeySet, config *Config) *TokenVerifier {
	return &TokenVerifier{keySet: keySet, config: config, issuer: issuerURL}
}

func (v *TokenVerifier) verifyClaims(t *Token) error {
	if !v.config.SkipClientIDCheck {
		if v.config.ClientID != "" {
			if !contains(t.Audience, v.config.ClientID) {
				return fmt.Errorf("oi4vp: expected audience %q got %q", v.config.ClientID, t.Audience)
			}
		} else {
			return fmt.Errorf("oi4vp: invalid configuration, clientID must be provided or SkipClientIDCheck must be set")
		}
	}

	if !v.config.SkipExpiryCheck {
		now := time.Now
		if v.config.Now != nil {
			now = v.config.Now
		}
		nowTime := now()

		if t.Expiry.Before(nowTime) {
			return &TokenExpiredError{Expiry: t.Expiry}
		}

		// If nbf claim is provided in token, ensure that it is indeed in the past.
		if t.NotBefore != nil {
			nbfTime := time.Time(*t.NotBefore)
			// Set to 5 minutes since this is what other OpenID Connect providers do to deal with clock skew.
			// https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/blob/6.12.2/src/Microsoft.IdentityModel.Tokens/TokenValidationParameters.cs#L149-L153
			leeway := 5 * time.Minute

			if nowTime.Add(leeway).Before(nbfTime) {
				return fmt.Errorf("oi4vp: current time %v before the nbf (not before) time: %v", nowTime, nbfTime)
			}
		}
	}

	return nil
}

func (v *TokenVerifier) Verify(ctx context.Context, rawToken string) (*Token, error) {
	payload, err := parseJWT(rawToken)
	if err != nil {
		return nil, fmt.Errorf("oi4vp: malformed jwt: %v", err)
	}

	var token genericToken
	if err := json.Unmarshal(payload, &token); err != nil {
		return nil, fmt.Errorf("oi4vp: failed to unmarshal claims: %v", err)
	}

	t := &Token{
		Issuer:    token.Issuer,
		Subject:   token.Subject,
		Audience:  []string(token.Audience),
		Expiry:    time.Time(token.Expiry),
		IssuedAt:  time.Time(token.IssuedAt),
		NotBefore: (*time.Time)(token.NotBefore),
		claims:    payload,
	}

	err = v.verifyClaims(t)
	if err != nil {
		return nil, err
	}

	if v.config.InsecureSkipSignatureCheck {
		return t, nil
	}

	jws, err := jose.ParseSigned(rawToken)
	if err != nil {
		return nil, fmt.Errorf("oi4vp: malformed jwt: %v", err)
	}

	switch len(jws.Signatures) {
	case 0:
		return nil, fmt.Errorf("oi4vp: id token not signed")
	case 1:
	default:
		return nil, fmt.Errorf("oi4vp: multiple signatures on id token not supported")
	}

	sig := jws.Signatures[0]
	supportedSigAlgs := v.config.SupportedSigningAlgs
	if len(supportedSigAlgs) == 0 {
		supportedSigAlgs = []string{RS256}
	}

	if !contains(supportedSigAlgs, sig.Header.Algorithm) {
		return nil, fmt.Errorf("oi4vp: id token signed with unsupported algorithm, expected %q got %q", supportedSigAlgs, sig.Header.Algorithm)
	}

	t.SigAlgorithm = sig.Header.Algorithm

	ctx = context.WithValue(ctx, parsedJWTKey, jws)
	gotPayload, err := v.keySet.VerifySignature(ctx, rawToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify signature: %v", err)
	}

	// Ensure that the payload returned by the square actually matches the payload parsed earlier.
	if !bytes.Equal(gotPayload, payload) {
		return nil, errors.New("oi4vp: internal error, payload parsed did not match previous payload")
	}

	return t, nil
}

type VPTokenVerifier struct {
	config      *Config
	Credentials []Token
}

func NewVPVerifier(config *Config) *VPTokenVerifier {
	return &VPTokenVerifier{config: config}
}

func (v *VPTokenVerifier) verifyClaims(t *Token) error {
	if !v.config.SkipClientIDCheck {
		if v.config.ClientID != "" {
			if !contains(t.Audience, v.config.ClientID) {
				return fmt.Errorf("oi4vp: expected audience %q got %q", v.config.ClientID, t.Audience)
			}
		} else {
			return fmt.Errorf("oi4vp: invalid configuration, clientID must be provided or SkipClientIDCheck must be set")
		}
	}

	if !v.config.SkipExpiryCheck {
		now := time.Now
		if v.config.Now != nil {
			now = v.config.Now
		}
		nowTime := now()

		if t.Expiry.Before(nowTime) {
			return &TokenExpiredError{Expiry: t.Expiry}
		}

		// If nbf claim is provided in token, ensure that it is indeed in the past.
		if t.NotBefore != nil {
			nbfTime := time.Time(*t.NotBefore)
			// Set to 5 minutes since this is what other OpenID Connect providers do to deal with clock skew.
			// https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/blob/6.12.2/src/Microsoft.IdentityModel.Tokens/TokenValidationParameters.cs#L149-L153
			leeway := 5 * time.Minute

			if nowTime.Add(leeway).Before(nbfTime) {
				return fmt.Errorf("oi4vp: current time %v before the nbf (not before) time: %v", nowTime, nbfTime)
			}
		}
	}

	return nil
}

func (v *VPTokenVerifier) verifySignature(t *Token, rawToken string) error {
	jws, err := jose.ParseSigned(rawToken)
	if err != nil {
		return fmt.Errorf("oi4vp: malformed jwt: %v", err)
	}

	switch len(jws.Signatures) {
	case 0:
		return fmt.Errorf("oi4vp: id token not signed")
	case 1:
	default:
		return fmt.Errorf("oi4vp: multiple signatures on id token not supported")
	}

	sig := jws.Signatures[0]

	if sig.Header.Algorithm != ES256K {
		return fmt.Errorf("oi4vp: vp token signed with unsupported algorithm, expected ES256K")
	}

	t.SigAlgorithm = sig.Header.Algorithm

	issuer := getIdentity(t.Issuer)
	signingStrParts := strings.Split(rawToken, ".")

	err = verifyES256K(issuer.Bytes(), []byte(strings.Join(signingStrParts[:2], ".")), sig.Signature)
	if err != nil {
		return fmt.Errorf("oi4vp: invalid signature: %v", err)
	}

	return nil
}

func (v *VPTokenVerifier) Verify(ctx context.Context, rawToken string) (*Token, error) {
	payload, err := parseJWT(rawToken)
	if err != nil {
		return nil, fmt.Errorf("oi4vp: malformed jwt: %v", err)
	}

	var token genericToken
	if err := json.Unmarshal(payload, &token); err != nil {
		return nil, fmt.Errorf("oi4vp: failed to unmarshal claims: %v", err)
	}

	if err := json.Unmarshal(payload, &token.Claims); err != nil {
		return nil, fmt.Errorf("oi4vp: failed to unmarshal public claims: %v", err)
	}

	t := &Token{
		Issuer:   token.Issuer,
		Subject:  token.Subject,
		Audience: []string(token.Audience),
		Expiry:   time.Time(token.Expiry),
		IssuedAt: time.Time(token.IssuedAt),
		claims:   payload,
	}

	err = v.verifyClaims(t)
	if err != nil {
		return nil, err
	}

	if v.config.InsecureSkipSignatureCheck {
		return t, nil
	}

	err = v.verifySignature(t, rawToken)
	if err != nil {
		return nil, err
	}

	credentials := token.Claims["vp"].(map[string]interface{})["verifiableCredential"].([]interface{})

	for _, credential := range credentials {
		payload, err := parseJWT(credential.(string))
		if err != nil {
			return nil, fmt.Errorf("oi4vp: malformed credential jwt: %v", err)
		}

		var token genericToken
		if err := json.Unmarshal(payload, &token); err != nil {
			return nil, fmt.Errorf("oi4vp: failed to unmarshal claims: %v", err)
		}

		if err := json.Unmarshal(payload, &token.Claims); err != nil {
			return nil, fmt.Errorf("oi4vp: failed to unmarshal public claims: %v", err)
		}

		t := &Token{
			Issuer:   token.Issuer,
			Subject:  token.Subject,
			Audience: []string(token.Audience),
			Expiry:   time.Time(token.Expiry),
			IssuedAt: time.Time(token.IssuedAt),
			claims:   payload,
		}

		v.Credentials = append(v.Credentials, *t)

		err = v.verifyClaims(t)
		if err != nil {
			return nil, err
		}

		if v.config.InsecureSkipSignatureCheck {
			return t, nil
		}

		err = v.verifySignature(t, credential.(string))
		if err != nil {
			return nil, err
		}
	}

	return t, nil
}

func Nonce(nonce string) oauth2.AuthCodeOption {
	return oauth2.SetAuthURLParam("nonce", nonce)
}

func getIdentity(did string) common.Address {
	ethrSegments := strings.Split(did, ":")
	identity := common.HexToAddress(ethrSegments[len(ethrSegments)-1])

	return identity
}

func verifyES256K(verificationKey []byte, data []byte, signature []byte) error {
	hasher := sha256.New()
	_, _ = hasher.Write(data)
	hash := hasher.Sum(nil)

	if len(verificationKey) == 20 {
		if len(signature) == 65 {
			if signature[crypto.RecoveryIDOffset] > 1 {
				signature[crypto.RecoveryIDOffset] -= 27 // Transform yellow paper V from 27/28 to 0/1
			}

			recPK, err := crypto.SigToPub(hash, signature)
			if err != nil {
				return fmt.Errorf("oi4vp: invalid signature: %v", err)
			}

			recAddress := crypto.PubkeyToAddress(*recPK)
			if slices.Equal(verificationKey, recAddress.Bytes()) {
				return nil
			}
		} else {
			var sigs [][]byte
			sigs = append(sigs, append(signature, 0), append(signature, 1))

			for _, sig := range sigs {
				recPK, err := crypto.SigToPub(hash, sig)
				if err != nil {
					return fmt.Errorf("oi4vp: invalid signature: %v", err)
				}

				recAddress := crypto.PubkeyToAddress(*recPK)
				if slices.Equal(verificationKey, recAddress.Bytes()) {
					return nil
				}
			}
		}

		return fmt.Errorf("oi4vp: invalid signature")
	} else {
		if !crypto.VerifySignature(verificationKey, hash, signature) {
			return fmt.Errorf("oi4vp: invalid signature")
		}
	}

	return nil
}
