package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/flosch/pongo2/v6"
	"github.com/gorilla/mux"
	"github.com/pass3id/identity-sdk/oi4vp"
	"golang.org/x/oauth2"
)

var (
	clientID     = os.Getenv("PASS3_OAUTH2_CLIENT_ID")
	clientSecret = os.Getenv("PASS3_OAUTH2_CLIENT_SECRET")
	sessionName  = "user-session"
	oauthConfig  *oauth2.Config
	oauthState   string
	oauthNonce   string
	kv           *KeyValue
)

var (
	authURL     = os.Getenv("PASS3_OAUTH2_AUTHORIZE_URL")
	tokenURL    = os.Getenv("PASS3_OAUTH2_TOKEN_URL")
	callbackURL = os.Getenv("PASS3_OAUTH2_CALLBACK_URL")
)

var tplHome = pongo2.Must(pongo2.FromFile("resource/home.html"))

func main() {
	kv = NewKeyValue()

	pconfig := oi4vp.ProviderConfig{
		AuthURL:  authURL,
		TokenURL: tokenURL,
	}
	provider := pconfig.NewProvider(context.Background())

	oauthConfig = &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  callbackURL,
		Scopes:       []string{oi4vp.LinkedIdentifiers},
	}

	oauthState = "prikitiw"
	oauthNonce = "the-nonce"

	router := mux.NewRouter()
	router.HandleFunc("/", homeHandler).Methods("GET")
	router.HandleFunc("/login", loginHandler).Methods("GET")
	router.HandleFunc("/logout", logoutHandler).Methods("GET")
	router.HandleFunc("/callback", callbackHandler).Methods("GET")
	router.HandleFunc("/credentials", credentialHandler).Methods("GET")

	router.HandleFunc("/authorize", authMockHandler).Methods("GET")
	router.HandleFunc("/token", tokenMockHandler).Methods("POST")

	log.Println("Starting server on port 8080...")
	err := http.ListenAndServe(":8080", router)
	if err != nil {
		log.Fatal("Server error:", err)
	}
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	c := &http.Cookie{}
	if storedCookie, _ := r.Cookie(sessionName); storedCookie != nil {
		c = storedCookie
	}

	linkURL := "/login"
	linkLabel := "PASS3 Login"
	credential := ""

	if c.Value != "" {
		data, available := kv.Get(c.Value)
		if available {
			linkURL = "/logout"
			linkLabel = "Logout"
			credential = data.(string)
		}
	}

	err := tplHome.ExecuteWriter(pongo2.Context{"linkURL": linkURL, "linkLabel": linkLabel, "credential": credential}, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	url := oauthConfig.AuthCodeURL(oauthState, oauth2.SetAuthURLParam("nonce", oauthNonce))
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	if storedCookie, _ := r.Cookie(sessionName); storedCookie != nil {
		if storedCookie.Value != "" {
			kv.Delete(storedCookie.Value)
		}

		storedCookie.Name = ""
		storedCookie.Value = ""
		http.SetCookie(w, storedCookie)
	}

	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
	state := r.FormValue("state")
	if state != oauthState {
		log.Println("Invalid OAuth state")
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	// Exchange the received code for a token
	code := r.FormValue("code")
	token, err := oauthConfig.Exchange(context.Background(), code)
	if err != nil {
		log.Println("OAuth token exchange error:", err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	// Verify the token
	verifier := oi4vp.NewVPVerifier(&oi4vp.Config{
		SkipClientIDCheck: true,
		SkipExpiryCheck:   true,
	})

	ctx := context.Background()
	_, err = verifier.Verify(ctx, token.Extra("vp_token").(string))
	if err != nil {
		log.Println("Verification error:", err)
	}

	// Build the claims
	var claims struct {
		VC map[string]interface{} `json:"vc"`
	}

	if err := verifier.Credentials[0].BuildClaims(&claims); err != nil {
		log.Println("Build claims error:", err)
	}

	data, err := json.MarshalIndent(claims.VC, "", "  ")
	if err != nil {
		log.Println("Build claims error:", err)
	}

	kv.Set(claims.VC["id"].(string), string(data), 15*time.Minute)

	c := &http.Cookie{}
	c.Name = sessionName
	c.Value = claims.VC["id"].(string)
	c.Expires = time.Now().Add(15 * time.Minute)
	http.SetCookie(w, c)

	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

func credentialHandler(w http.ResponseWriter, r *http.Request) {
	c := &http.Cookie{}
	if storedCookie, _ := r.Cookie(sessionName); storedCookie != nil {
		c = storedCookie
	}

	if c.Value != "" {
		data, available := kv.Get(c.Value)
		if !available {
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}

		fmt.Fprintln(w, data)
	}
}

func authMockHandler(w http.ResponseWriter, r *http.Request) {
	values := url.Values{}
	values.Add("state", r.FormValue("state"))
	values.Add("nonce", r.FormValue("nonce"))
	query := values.Encode()

	redirectUri := r.FormValue("redirect_uri")

	http.Redirect(w, r, redirectUri+"?"+query, http.StatusTemporaryRedirect)
}

func tokenMockHandler(w http.ResponseWriter, r *http.Request) {
	type TokenResponse struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		VPToken     string `json:"vp_token"`
	}

	response := &TokenResponse{
		AccessToken: "1234567890",
		TokenType:   "Bearer",
		VPToken:     "eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6ZXRocjoweDk2ODU5ODQyYUExRmJlY2Y0QzZiN0IwN2Y2ZjI2YkJkODhGMTMyZDUjY29udHJvbGxlciIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJkaWQ6ZXRocjoweDk2ODU5ODQyYUExRmJlY2Y0QzZiN0IwN2Y2ZjI2YkJkODhGMTMyZDUiLCJ2cCI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVQcmVzZW50YXRpb24iXSwiaG9sZGVyIjoiZGlkOmV0aHI6MHg5Njg1OTg0MmFBMUZiZWNmNEM2YjdCMDdmNmYyNmJCZDg4RjEzMmQ1IiwidmVyaWZpYWJsZUNyZWRlbnRpYWwiOlsiZXlKaGJHY2lPaUpGVXpJMU5rc2lMQ0pyYVdRaU9pSmthV1E2WlhSb2Nqb3dlRGc1UWtNNU1XRXpNelEwTVRSaU9ETkNNREU1TkRjMU9ERTFaak5rT1dZMU56WTJaREV4UkdNalkyOXVkSEp2Ykd4bGNpSXNJblI1Y0NJNklrcFhWQ0o5LmV5SnBjM01pT2lKa2FXUTZaWFJvY2pvd2VEZzVRa001TVdFek16UTBNVFJpT0ROQ01ERTVORGMxT0RFMVpqTmtPV1kxTnpZMlpERXhSR01pTENKemRXSWlPaUprYVdRNlpYUm9jam93ZURrMk9EVTVPRFF5WVVFeFJtSmxZMlkwUXpaaU4wSXdOMlkyWmpJMllrSmtPRGhHTVRNeVpEVWlMQ0p1WW1ZaU9qRTJPRFEwTnpnek9ERXNJbWxoZENJNk1UWTRORFEzT0RNNE1Td2lhblJwSWpvaWFIUjBjSE02THk5d1lYTnpNeTVwWkM5amNtVmtaVzUwYVdGc2N5OXNhVzVyWldRdGFXUmxiblJwWm1sbGNuTXZNelJsT0RBd09URXRaVGhsTXkwME5UZGlMV0UzTTJNdFlqZGhPV014TjJZMlpEVmhJaXdpZG1NaU9uc2lRR052Ym5SbGVIUWlPbHNpYUhSMGNITTZMeTkzZDNjdWR6TXViM0puTHpJd01UZ3ZZM0psWkdWdWRHbGhiSE12ZGpFaUxDSm9kSFJ3Y3pvdkwzTndaV056TG5CaGMzTXpMbWxrTDJOeVpXUmxiblJwWVd4ekwyeHBibXRsWkMxcFpHVnVkR2xtYVdWeWN5MTJNU0lzSW1oMGRIQnpPaTh2ZHpOcFpDNXZjbWN2ZG1NdmMzUmhkSFZ6TFd4cGMzUXZNakF5TVM5Mk1TSmRMQ0pwWkNJNkltaDBkSEJ6T2k4dmNHRnpjek11YVdRdlkzSmxaR1Z1ZEdsaGJITXZiR2x1YTJWa0xXbGtaVzUwYVdacFpYSnpMek0wWlRnd01Ea3hMV1U0WlRNdE5EVTNZaTFoTnpOakxXSTNZVGxqTVRkbU5tUTFZU0lzSW5SNWNHVWlPbHNpVm1WeWFXWnBZV0pzWlVOeVpXUmxiblJwWVd3aUxDSk1hVzVyWldSSlpHVnVkR2xtYVdWeWN5SmRMQ0pwYzNOMVpYSWlPaUprYVdRNlpYUm9jam93ZURnNVFrTTVNV0V6TXpRME1UUmlPRE5DTURFNU5EYzFPREUxWmpOa09XWTFOelkyWkRFeFJHTWlMQ0pwYzNOMVlXNWpaVVJoZEdVaU9pSXlNREl6TFRBMUxURTVWREEyT2pNNU9qUXhXaUlzSW1OeVpXUmxiblJwWVd4VGRXSnFaV04wSWpwN0ltVnRZV2xzWDJGa1pISmxjM05sY3lJNlczc2laVzFoYVd4ZllXUmtjbVZ6Y3lJNkluUnZhMlZ1UUdkdFlXbHNMbU52YlNJc0luWmxjbWxtYVdOaGRHbHZiaUk2ZXlKemRHRjBkWE1pT2lKMlpYSnBabWxsWkNKOWZWMHNJbWxrSWpvaVpHbGtPbVYwYUhJNk1IZzVOamcxT1RnME1tRkJNVVppWldObU5FTTJZamRDTURkbU5tWXlObUpDWkRnNFJqRXpNbVExSWl3aWQyRnNiR1YwWDJGa1pISmxjM05sY3lJNlczc2liR1ZrWjJWeUlqb2laWFJvWlhKbGRXMGlMQ0p3Y205MmFXUmxjaUk2ZXlKa2IyMWhhVzRpT2lKd1lYTnpNeTVwWkNKOUxDSjJaWEpwWm1sallYUnBiMjRpT25zaWMzUmhkSFZ6SWpvaWRtVnlhV1pwWldRaWZTd2lkMkZzYkdWMFgyRmtaSEpsYzNNaU9pSXdlRGsyT0RVNU9EUXlZVUV4Um1KbFkyWTBRelppTjBJd04yWTJaakkyWWtKa09EaEdNVE15WkRVaWZWMHNJbmRsWWw5aFkyTnZkVzUwY3lJNlczc2lhV1FpT2lKTFZYTXdZVEF3TURSa2FHNDVPRGw2WkdVaUxDSndjbTkyYVdSbGNpSTZleUprYjIxaGFXNGlPaUp3WVhOek15NXBaQ0o5TENKMlpYSnBabWxqWVhScGIyNGlPbnNpYzNSaGRIVnpJam9pZG1WeWFXWnBaV1FpZlgxZGZTd2lZM0psWkdWdWRHbGhiRk5qYUdWdFlTSTZleUpwWkNJNkltaDBkSEJ6T2k4dmMzQmxZM011Y0dGemN6TXVhV1F2YkdsdWEyVmtMV2xrWlc1MGFXWnBaWEp6TFhOamFHVnRZUzB4TGpBaUxDSjBlWEJsSWpvaVEzSmxaR1Z1ZEdsaGJGTmphR1Z0WVRJd01qSWlmU3dpWTNKbFpHVnVkR2xoYkZOMFlYUjFjeUk2ZXlKcFpDSTZJbWgwZEhBNkx5OXNiMk5oYkdodmMzUTZPRE00TUM4dkwzWmpiUzl5WlhOMEwzWXhMMk55WldSbGJuUnBZV3d2YzNSaGRIVnpMekFqTVNJc0luTjBZWFIxYzB4cGMzUkRjbVZrWlc1MGFXRnNJam9pYUhSMGNEb3ZMMnh2WTJGc2FHOXpkRG80TXpnd0x5OHZkbU50TDNKbGMzUXZkakV2WTNKbFpHVnVkR2xoYkM5emRHRjBkWE12TUNJc0luTjBZWFIxYzB4cGMzUkpibVJsZUNJNklqRWlMQ0p6ZEdGMGRYTlFkWEp3YjNObElqb2ljbVYyYjJOaGRHbHZiaUlzSW5SNWNHVWlPaUpUZEdGMGRYTk1hWE4wTWpBeU1VVnVkSEo1SW4xOWZRLkxYVnZWTGdEeHk2QkxzZmd3dUJXZC13Q1pDTnR3TG1seU5MdDl4ekZzdXBOU2VTTlpSMkVqWHU4NHlhYlZDSjVfSTNBQ1BSZGR1Z3luVDU0OVJ0TXdBIl19fQ.kKF9lij36Qo2UTQbbSqBU8x3cwv6qbZcHokhnUpqlH8IpbF9DjZT5yXRmbnVEPfRJ5h73z-SOlGQ-6ckF-Y5HA",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
