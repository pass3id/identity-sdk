package oi4vp

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"testing"
	"time"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

func TestVerify(t *testing.T) {
	tests := []verificationTest{
		{
			name:    "good token",
			vpToken: `{"iss":"https://foo"}`,
			config: Config{
				SkipClientIDCheck: true,
				SkipExpiryCheck:   true,
			},
			signKey: newRSAKey(t),
		},
		{
			name:    "good eddsa token",
			vpToken: `{"iss":"https://foo"}`,
			config: Config{
				SkipClientIDCheck:    true,
				SkipExpiryCheck:      true,
				SupportedSigningAlgs: []string{EdDSA},
			},
			signKey: newEdDSAKey(t),
		},
		{
			name:    "invalid sig",
			vpToken: `{"iss":"https://foo"}`,
			config: Config{
				SkipClientIDCheck: true,
				SkipExpiryCheck:   true,
			},
			signKey:         newRSAKey(t),
			verificationKey: newRSAKey(t),
			wantErr:         true,
		},
		{
			name:    "expired token",
			vpToken: `{"iss":"https://foo","exp":` + strconv.FormatInt(time.Now().Add(-time.Hour).Unix(), 10) + `}`,
			config: Config{
				SkipClientIDCheck: true,
			},
			signKey:       newRSAKey(t),
			wantErrExpiry: true,
		},
		{
			name:    "unexpired token",
			vpToken: `{"iss":"https://foo","exp":` + strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10) + `}`,
			config: Config{
				SkipClientIDCheck: true,
			},
			signKey: newRSAKey(t),
		},
		{
			name: "expiry as float",
			vpToken: `{"iss":"https://foo","exp":` +
				strconv.FormatFloat(float64(time.Now().Add(time.Hour).Unix()), 'E', -1, 64) +
				`}`,
			config: Config{
				SkipClientIDCheck: true,
			},
			signKey: newRSAKey(t),
		},
		{
			name: "nbf in future",
			vpToken: `{"iss":"https://foo","nbf":` + strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10) +
				`,"exp":` + strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10) + `}`,
			config: Config{
				SkipClientIDCheck: true,
			},
			signKey: newRSAKey(t),
			wantErr: true,
		},
		{
			name: "nbf in past",
			vpToken: `{"iss":"https://foo","nbf":` + strconv.FormatInt(time.Now().Add(-time.Hour).Unix(), 10) +
				`,"exp":` + strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10) + `}`,
			config: Config{
				SkipClientIDCheck: true,
			},
			signKey: newRSAKey(t),
		},
		{
			name: "nbf in future within clock skew tolerance",
			vpToken: `{"iss":"https://foo","nbf":` + strconv.FormatInt(time.Now().Add(30*time.Second).Unix(), 10) +
				`,"exp":` + strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10) + `}`,
			config: Config{
				SkipClientIDCheck: true,
			},
			signKey: newRSAKey(t),
		},
		{
			name:    "unsigned token",
			vpToken: `{"iss":"https://foo"}`,
			config: Config{
				SkipClientIDCheck: true,
				SkipExpiryCheck:   true,
			},
			wantErr: true,
		},
		{
			name:    "unsigned token InsecureSkipSignatureCheck",
			vpToken: `{"iss":"https://foo"}`,
			config: Config{
				SkipClientIDCheck:          true,
				SkipExpiryCheck:            true,
				InsecureSkipSignatureCheck: true,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, test.run)
	}
}

func TestVerifyAudience(t *testing.T) {
	tests := []verificationTest{
		{
			name:    "good audience",
			vpToken: `{"iss":"https://foo","aud":"client1"}`,
			config: Config{
				ClientID:        "client1",
				SkipExpiryCheck: true,
			},
			signKey: newRSAKey(t),
		},
		{
			name:    "mismatched audience",
			vpToken: `{"iss":"https://foo","aud":"client2"}`,
			config: Config{
				ClientID:        "client1",
				SkipExpiryCheck: true,
			},
			signKey: newRSAKey(t),
			wantErr: true,
		},
		{
			name:    "multiple audiences, one matches",
			vpToken: `{"iss":"https://foo","aud":["client1","client2"]}`,
			config: Config{
				ClientID:        "client2",
				SkipExpiryCheck: true,
			},
			signKey: newRSAKey(t),
		},
	}
	for _, test := range tests {
		t.Run(test.name, test.run)
	}
}

func TestVerifySigningAlg(t *testing.T) {
	tests := []verificationTest{
		{
			name:    "default signing alg",
			vpToken: `{"iss":"https://foo"}`,
			config: Config{
				SkipClientIDCheck: true,
				SkipExpiryCheck:   true,
			},
			signKey: newRSAKey(t),
		},
		{
			name:    "bad signing alg",
			vpToken: `{"iss":"https://foo"}`,
			config: Config{
				SkipClientIDCheck: true,
				SkipExpiryCheck:   true,
			},
			signKey: newECDSAKey(t),
			wantErr: true,
		},
		{
			name:    "ecdsa signing",
			vpToken: `{"iss":"https://foo"}`,
			config: Config{
				SupportedSigningAlgs: []string{ES256},
				SkipClientIDCheck:    true,
				SkipExpiryCheck:      true,
			},
			signKey: newECDSAKey(t),
		},
		{
			name:    "eddsa signing",
			vpToken: `{"iss":"https://foo"}`,
			config: Config{
				SkipClientIDCheck:    true,
				SkipExpiryCheck:      true,
				SupportedSigningAlgs: []string{EdDSA},
			},
			signKey: newEdDSAKey(t),
		},
		{
			name:    "one of many supported",
			vpToken: `{"iss":"https://foo"}`,
			config: Config{
				SkipClientIDCheck:    true,
				SkipExpiryCheck:      true,
				SupportedSigningAlgs: []string{RS256, ES256},
			},
			signKey: newECDSAKey(t),
		},
		{
			name:    "not in requiredAlgs",
			vpToken: `{"iss":"https://foo"}`,
			config: Config{
				SupportedSigningAlgs: []string{RS256, ES512},
				SkipClientIDCheck:    true,
				SkipExpiryCheck:      true,
			},
			signKey: newECDSAKey(t),
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, test.run)
	}
}

func TestVPVerify(t *testing.T) {
	vp := `eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6ZXRocjoweDk2ODU5ODQyYUExRmJlY2Y0QzZiN0IwN2Y2ZjI2YkJkODhGMTMyZDUjY29udHJvbGxlciIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJkaWQ6ZXRocjoweDk2ODU5ODQyYUExRmJlY2Y0QzZiN0IwN2Y2ZjI2YkJkODhGMTMyZDUiLCJ2cCI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVQcmVzZW50YXRpb24iXSwiaG9sZGVyIjoiZGlkOmV0aHI6MHg5Njg1OTg0MmFBMUZiZWNmNEM2YjdCMDdmNmYyNmJCZDg4RjEzMmQ1IiwidmVyaWZpYWJsZUNyZWRlbnRpYWwiOlsiZXlKaGJHY2lPaUpGVXpJMU5rc2lMQ0pyYVdRaU9pSmthV1E2WlhSb2Nqb3dlRGc1UWtNNU1XRXpNelEwTVRSaU9ETkNNREU1TkRjMU9ERTFaak5rT1dZMU56WTJaREV4UkdNalkyOXVkSEp2Ykd4bGNpSXNJblI1Y0NJNklrcFhWQ0o5LmV5SnBjM01pT2lKa2FXUTZaWFJvY2pvd2VEZzVRa001TVdFek16UTBNVFJpT0ROQ01ERTVORGMxT0RFMVpqTmtPV1kxTnpZMlpERXhSR01pTENKemRXSWlPaUprYVdRNlpYUm9jam93ZURrMk9EVTVPRFF5WVVFeFJtSmxZMlkwUXpaaU4wSXdOMlkyWmpJMllrSmtPRGhHTVRNeVpEVWlMQ0p1WW1ZaU9qRTJPRFEwTnpnek9ERXNJbWxoZENJNk1UWTRORFEzT0RNNE1Td2lhblJwSWpvaWFIUjBjSE02THk5d1lYTnpNeTVwWkM5amNtVmtaVzUwYVdGc2N5OXNhVzVyWldRdGFXUmxiblJwWm1sbGNuTXZNelJsT0RBd09URXRaVGhsTXkwME5UZGlMV0UzTTJNdFlqZGhPV014TjJZMlpEVmhJaXdpZG1NaU9uc2lRR052Ym5SbGVIUWlPbHNpYUhSMGNITTZMeTkzZDNjdWR6TXViM0puTHpJd01UZ3ZZM0psWkdWdWRHbGhiSE12ZGpFaUxDSm9kSFJ3Y3pvdkwzTndaV056TG5CaGMzTXpMbWxrTDJOeVpXUmxiblJwWVd4ekwyeHBibXRsWkMxcFpHVnVkR2xtYVdWeWN5MTJNU0lzSW1oMGRIQnpPaTh2ZHpOcFpDNXZjbWN2ZG1NdmMzUmhkSFZ6TFd4cGMzUXZNakF5TVM5Mk1TSmRMQ0pwWkNJNkltaDBkSEJ6T2k4dmNHRnpjek11YVdRdlkzSmxaR1Z1ZEdsaGJITXZiR2x1YTJWa0xXbGtaVzUwYVdacFpYSnpMek0wWlRnd01Ea3hMV1U0WlRNdE5EVTNZaTFoTnpOakxXSTNZVGxqTVRkbU5tUTFZU0lzSW5SNWNHVWlPbHNpVm1WeWFXWnBZV0pzWlVOeVpXUmxiblJwWVd3aUxDSk1hVzVyWldSSlpHVnVkR2xtYVdWeWN5SmRMQ0pwYzNOMVpYSWlPaUprYVdRNlpYUm9jam93ZURnNVFrTTVNV0V6TXpRME1UUmlPRE5DTURFNU5EYzFPREUxWmpOa09XWTFOelkyWkRFeFJHTWlMQ0pwYzNOMVlXNWpaVVJoZEdVaU9pSXlNREl6TFRBMUxURTVWREEyT2pNNU9qUXhXaUlzSW1OeVpXUmxiblJwWVd4VGRXSnFaV04wSWpwN0ltVnRZV2xzWDJGa1pISmxjM05sY3lJNlczc2laVzFoYVd4ZllXUmtjbVZ6Y3lJNkluUnZhMlZ1UUdkdFlXbHNMbU52YlNJc0luWmxjbWxtYVdOaGRHbHZiaUk2ZXlKemRHRjBkWE1pT2lKMlpYSnBabWxsWkNKOWZWMHNJbWxrSWpvaVpHbGtPbVYwYUhJNk1IZzVOamcxT1RnME1tRkJNVVppWldObU5FTTJZamRDTURkbU5tWXlObUpDWkRnNFJqRXpNbVExSWl3aWQyRnNiR1YwWDJGa1pISmxjM05sY3lJNlczc2liR1ZrWjJWeUlqb2laWFJvWlhKbGRXMGlMQ0p3Y205MmFXUmxjaUk2ZXlKa2IyMWhhVzRpT2lKd1lYTnpNeTVwWkNKOUxDSjJaWEpwWm1sallYUnBiMjRpT25zaWMzUmhkSFZ6SWpvaWRtVnlhV1pwWldRaWZTd2lkMkZzYkdWMFgyRmtaSEpsYzNNaU9pSXdlRGsyT0RVNU9EUXlZVUV4Um1KbFkyWTBRelppTjBJd04yWTJaakkyWWtKa09EaEdNVE15WkRVaWZWMHNJbmRsWWw5aFkyTnZkVzUwY3lJNlczc2lhV1FpT2lKTFZYTXdZVEF3TURSa2FHNDVPRGw2WkdVaUxDSndjbTkyYVdSbGNpSTZleUprYjIxaGFXNGlPaUp3WVhOek15NXBaQ0o5TENKMlpYSnBabWxqWVhScGIyNGlPbnNpYzNSaGRIVnpJam9pZG1WeWFXWnBaV1FpZlgxZGZTd2lZM0psWkdWdWRHbGhiRk5qYUdWdFlTSTZleUpwWkNJNkltaDBkSEJ6T2k4dmMzQmxZM011Y0dGemN6TXVhV1F2YkdsdWEyVmtMV2xrWlc1MGFXWnBaWEp6TFhOamFHVnRZUzB4TGpBaUxDSjBlWEJsSWpvaVEzSmxaR1Z1ZEdsaGJGTmphR1Z0WVRJd01qSWlmU3dpWTNKbFpHVnVkR2xoYkZOMFlYUjFjeUk2ZXlKcFpDSTZJbWgwZEhBNkx5OXNiMk5oYkdodmMzUTZPRE00TUM4dkwzWmpiUzl5WlhOMEwzWXhMMk55WldSbGJuUnBZV3d2YzNSaGRIVnpMekFqTVNJc0luTjBZWFIxYzB4cGMzUkRjbVZrWlc1MGFXRnNJam9pYUhSMGNEb3ZMMnh2WTJGc2FHOXpkRG80TXpnd0x5OHZkbU50TDNKbGMzUXZkakV2WTNKbFpHVnVkR2xoYkM5emRHRjBkWE12TUNJc0luTjBZWFIxYzB4cGMzUkpibVJsZUNJNklqRWlMQ0p6ZEdGMGRYTlFkWEp3YjNObElqb2ljbVYyYjJOaGRHbHZiaUlzSW5SNWNHVWlPaUpUZEdGMGRYTk1hWE4wTWpBeU1VVnVkSEo1SW4xOWZRLkxYVnZWTGdEeHk2QkxzZmd3dUJXZC13Q1pDTnR3TG1seU5MdDl4ekZzdXBOU2VTTlpSMkVqWHU4NHlhYlZDSjVfSTNBQ1BSZGR1Z3luVDU0OVJ0TXdBIl19fQ.kKF9lij36Qo2UTQbbSqBU8x3cwv6qbZcHokhnUpqlH8IpbF9DjZT5yXRmbnVEPfRJ5h73z-SOlGQ-6ckF-Y5HA`

	verifier := NewVPVerifier(&Config{
		SkipClientIDCheck: true,
		SkipExpiryCheck:   true,
	})
	ctx := context.Background()
	_, err := verifier.Verify(ctx, vp)

	if err != nil {
		t.Errorf("%v", err)
	}

	var claims struct {
		VC map[string]interface{} `json:"vc"`
	}

	if err := verifier.Credentials[0].BuildClaims(&claims); err != nil {
		t.Errorf("%v", err)
	}
}

func TestVerifyES256K(t *testing.T) {
	arr := []int{1, 2, 3, 4, 5}

	for range arr {
		privateKey, err := ethcrypto.GenerateKey()
		if err != nil {
			fmt.Println("Error generating private key:", err)
			return
		}

		publicKey := privateKey.Public()
		publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			fmt.Println("Error getting public key")
			return
		}

		address := ethcrypto.PubkeyToAddress(*publicKeyECDSA).Bytes()

		hasher := sha256.New()
		_, _ = hasher.Write([]byte("hello world"))
		hash := hasher.Sum(nil)

		sig, _ := ethcrypto.Sign(hash, privateKey)

		err = verifyES256K(address, []byte("hello world"), sig)
		if err != nil {
			t.Errorf("%v", err)
		}
	}
}

type verificationTest struct {
	// Name of the subtest.
	name string

	// If not provided defaults to "https://foo"
	issuer string

	// JWT payload (just the claims).
	vpToken string

	// Key to sign the ID Token with.
	signKey *signingKey
	// If not provided defaults to signKey. Only useful when
	// testing invalid signatures.
	verificationKey *signingKey

	config        Config
	wantErr       bool
	wantErrExpiry bool
}

func (v verificationTest) runGetToken(t *testing.T) (*Token, error) {
	var token string
	if v.signKey != nil {
		token = v.signKey.sign(t, []byte(v.vpToken))
	} else {
		token = base64.RawURLEncoding.EncodeToString([]byte(`{alg: "none"}`))
		token += "."
		token += base64.RawURLEncoding.EncodeToString([]byte(v.vpToken))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	issuer := "https://foo"
	if v.issuer != "" {
		issuer = v.issuer
	}
	var ks KeySet
	if v.verificationKey != nil {
		ks = &StaticKeySet{PublicKeys: []crypto.PublicKey{v.verificationKey.pub}}
	} else if v.signKey != nil {
		ks = &StaticKeySet{PublicKeys: []crypto.PublicKey{v.signKey.pub}}
	}
	verifier := NewVerifier(issuer, ks, &v.config)

	return verifier.Verify(ctx, token)
}

func (v verificationTest) run(t *testing.T) {
	_, err := v.runGetToken(t)
	if err != nil && !v.wantErr && !v.wantErrExpiry {
		t.Errorf("%v", err)
	}
	if err == nil && (v.wantErr || v.wantErrExpiry) {
		t.Errorf("expected error")
	}
	if v.wantErrExpiry {
		var errExp *TokenExpiredError
		if !errors.As(err, &errExp) {
			t.Errorf("expected *TokenExpiryError but got %q", err)
		}
	}
}
