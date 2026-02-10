package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os/exec"
	"sort"
	"strings"
	"time"

	"xurl/config"
	xurlErrors "xurl/errors"
	"xurl/store"

	"runtime"

	"golang.org/x/oauth2"
)

type Auth struct {
	TokenStore           *store.TokenStore
	infoURL              string
	clientID             string
	clientSecret         string
	authURL              string
	tokenURL             string
	redirectURI          string
	consumerKey          string
	consumerSecret       string
	oauth1RequestTokenURL string
	oauth1AuthorizeURL   string
	oauth1AccessTokenURL string
}

// NewAuth creates a new Auth object
func NewAuth(config *config.Config) *Auth {
	return &Auth{
		TokenStore:           store.NewTokenStore(),
		infoURL:              config.InfoURL,
		clientID:             config.ClientID,
		clientSecret:         config.ClientSecret,
		authURL:              config.AuthURL,
		tokenURL:             config.TokenURL,
		redirectURI:          config.RedirectURI,
		consumerKey:          config.ConsumerKey,
		consumerSecret:       config.ConsumerSecret,
		oauth1RequestTokenURL: config.OAuth1RequestTokenURL,
		oauth1AuthorizeURL:   config.OAuth1AuthorizeURL,
		oauth1AccessTokenURL: config.OAuth1AccessTokenURL,
	}
}

// WithTokenStore sets the token store for the Auth object
func (a *Auth) WithTokenStore(tokenStore *store.TokenStore) *Auth {
	a.TokenStore = tokenStore
	return a
}

// SetConsumerCredentials sets consumer key and secret for OAuth1 flow (used by CLI flag overrides)
func (a *Auth) SetConsumerCredentials(consumerKey, consumerSecret string) {
	a.consumerKey = consumerKey
	a.consumerSecret = consumerSecret
}

// GetOAuth1Header gets the OAuth1 header for a request using stored tokens
func (a *Auth) GetOAuth1Header(method, urlStr string, additionalParams map[string]string) (string, error) {
	token := a.TokenStore.GetOAuth1Tokens()
	if token == nil || token.OAuth1 == nil {
		return "", xurlErrors.NewAuthError("TokenNotFound", errors.New("OAuth1 token not found"))
	}

	oauth1Token := token.OAuth1
	return buildOAuth1AuthHeader(method, urlStr, oauth1Token.ConsumerKey, oauth1Token.ConsumerSecret, oauth1Token.AccessToken, oauth1Token.TokenSecret, additionalParams)
}

// buildOAuth1AuthHeader builds an OAuth1 Authorization header with explicit credentials.
// When oauthToken is empty, the oauth_token parameter is omitted from the header (used for request token step).
// Any additional params (like oauth_callback) are included in signing and in the header if they start with "oauth_".
func buildOAuth1AuthHeader(method, urlStr, consumerKey, consumerSecret, oauthToken, tokenSecret string, additionalParams map[string]string) (string, error) {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return "", xurlErrors.NewAuthError("InvalidURL", err)
	}

	params := make(map[string]string)

	query := parsedURL.Query()
	for key := range query {
		params[key] = query.Get(key)
	}

	for key, value := range additionalParams {
		params[key] = value
	}

	params["oauth_consumer_key"] = consumerKey
	params["oauth_nonce"] = generateNonce()
	params["oauth_signature_method"] = "HMAC-SHA1"
	params["oauth_timestamp"] = generateTimestamp()
	if oauthToken != "" {
		params["oauth_token"] = oauthToken
	}
	params["oauth_version"] = "1.0"

	signature, err := generateSignature(method, urlStr, params, consumerSecret, tokenSecret)
	if err != nil {
		return "", xurlErrors.NewAuthError("SignatureGenerationError", err)
	}

	var oauthParams []string
	oauthParams = append(oauthParams, fmt.Sprintf("oauth_consumer_key=\"%s\"", encode(consumerKey)))
	oauthParams = append(oauthParams, fmt.Sprintf("oauth_nonce=\"%s\"", encode(params["oauth_nonce"])))
	oauthParams = append(oauthParams, fmt.Sprintf("oauth_signature=\"%s\"", encode(signature)))
	oauthParams = append(oauthParams, fmt.Sprintf("oauth_signature_method=\"%s\"", encode("HMAC-SHA1")))
	oauthParams = append(oauthParams, fmt.Sprintf("oauth_timestamp=\"%s\"", encode(params["oauth_timestamp"])))
	if oauthToken != "" {
		oauthParams = append(oauthParams, fmt.Sprintf("oauth_token=\"%s\"", encode(oauthToken)))
	}
	oauthParams = append(oauthParams, fmt.Sprintf("oauth_version=\"%s\"", encode("1.0")))

	// Include additional oauth_ params (like oauth_callback) in the header
	for key, value := range additionalParams {
		if strings.HasPrefix(key, "oauth_") {
			oauthParams = append(oauthParams, fmt.Sprintf("%s=\"%s\"", key, encode(value)))
		}
	}

	return "OAuth " + strings.Join(oauthParams, ", "), nil
}

// GetOAuth2Token gets or refreshes an OAuth2 token
func (a *Auth) GetOAuth2Header(username string) (string, error) {
	var token *store.Token

	if username != "" {
		token = a.TokenStore.GetOAuth2Token(username)
	} else {
		token = a.TokenStore.GetFirstOAuth2Token()
	}

	if token == nil {
		return a.OAuth2Flow(username)
	}

	accessToken, err := a.RefreshOAuth2Token(username)
	if err != nil {
		return "", xurlErrors.NewAuthError("RefreshTokenError", err)
	}
	return "Bearer " + accessToken, nil
}

// OAuth2Flow starts the OAuth2 flow
func (a *Auth) OAuth2Flow(username string) (string, error) {
	config := &oauth2.Config{
		ClientID:     a.clientID,
		ClientSecret: a.clientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  a.authURL,
			TokenURL: a.tokenURL,
		},
		RedirectURL: a.redirectURI,
		Scopes:      getOAuth2Scopes(),
	}

	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", xurlErrors.NewAuthError("IOError", err)
	}
	state := base64.StdEncoding.EncodeToString(b)

	verifier, challenge := generateCodeVerifierAndChallenge()

	authURL := config.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"))

	err := openBrowser(authURL)
	if err != nil {
		fmt.Println("Failed to open browser automatically. Please visit this URL manually:")
		fmt.Println(authURL)
	}

	codeChan := make(chan string, 1)

	callback := func(code, receivedState string) error {
		if receivedState != state {
			return xurlErrors.NewAuthError("InvalidState", errors.New("invalid state parameter"))
		}

		if code == "" {
			return xurlErrors.NewAuthError("InvalidCode", errors.New("empty authorization code"))
		}

		codeChan <- code
		return nil
	}

	go func() {
		parsedURL, err := url.Parse(a.redirectURI)
		if err != nil {
			codeChan <- ""
			return
		}

		port := 8080
		if parsedURL.Port() != "" {
			fmt.Sscanf(parsedURL.Port(), "%d", &port)
		}

		if err := StartListener(port, callback); err != nil {
			fmt.Printf("Error in OAuth listener: %v\n", err)
		}
	}()

	var code string
	select {
	case code = <-codeChan:
		if code == "" {
			return "", xurlErrors.NewAuthError("ListenerError", errors.New("oauth2 listener failed"))
		}
	case <-time.After(5 * time.Minute):
		return "", xurlErrors.NewAuthError("Timeout", errors.New("authentication timed out"))
	}

	token, err := config.Exchange(context.Background(), code, oauth2.SetAuthURLParam("code_verifier", verifier))
	if err != nil {
		return "", xurlErrors.NewAuthError("TokenExchangeError", err)
	}

	var usernameStr string
	if username != "" {
		usernameStr = username
	} else {
		fetchedUsername, err := a.fetchUsername(token.AccessToken)
		if err != nil {
			return "", err
		}
		usernameStr = fetchedUsername
	}

	expirationTime := uint64(time.Now().Add(time.Duration(token.Expiry.Unix()-time.Now().Unix()) * time.Second).Unix())

	err = a.TokenStore.SaveOAuth2Token(usernameStr, token.AccessToken, token.RefreshToken, expirationTime)
	if err != nil {
		return "", xurlErrors.NewAuthError("TokenStorageError", err)
	}

	return token.AccessToken, nil
}

// RefreshOAuth2Token validates and refreshes an OAuth2 token if needed
func (a *Auth) RefreshOAuth2Token(username string) (string, error) {
	var token *store.Token

	if username != "" {
		token = a.TokenStore.GetOAuth2Token(username)
	} else {
		token = a.TokenStore.GetFirstOAuth2Token()
	}

	if token == nil || token.OAuth2 == nil {
		return "", xurlErrors.NewAuthError("TokenNotFound", errors.New("oauth2 token not found"))
	}

	currentTime := time.Now().Unix()
	if uint64(currentTime) < token.OAuth2.ExpirationTime {
		return token.OAuth2.AccessToken, nil
	}

	config := &oauth2.Config{
		ClientID:     a.clientID,
		ClientSecret: a.clientSecret,
		Endpoint: oauth2.Endpoint{
			TokenURL: a.tokenURL,
		},
	}

	tokenSource := config.TokenSource(context.Background(), &oauth2.Token{
		RefreshToken: token.OAuth2.RefreshToken,
	})

	newToken, err := tokenSource.Token()
	if err != nil {
		return "", xurlErrors.NewAuthError("RefreshTokenError", err)
	}

	var usernameStr string
	if username != "" {
		usernameStr = username
	} else {
		fetchedUsername, err := a.fetchUsername(newToken.AccessToken)
		if err != nil {
			return "", xurlErrors.NewAuthError("UsernameFetchError", err)
		}
		usernameStr = fetchedUsername
	}

	expirationTime := uint64(time.Now().Add(time.Duration(newToken.Expiry.Unix()-time.Now().Unix()) * time.Second).Unix())

	err = a.TokenStore.SaveOAuth2Token(usernameStr, newToken.AccessToken, newToken.RefreshToken, expirationTime)
	if err != nil {
		return "", xurlErrors.NewAuthError("RefreshTokenError", err)
	}

	return newToken.AccessToken, nil
}

// GetBearerTokenHeader gets the bearer token from the token store
func (a *Auth) GetBearerTokenHeader() (string, error) {
	token := a.TokenStore.GetBearerToken()
	if token == nil {
		return "", xurlErrors.NewAuthError("TokenNotFound", errors.New("bearer token not found"))
	}
	return "Bearer " + token.Bearer, nil
}

func (a *Auth) fetchUsername(accessToken string) (string, error) {
	req, err := http.NewRequest("GET", a.infoURL, nil)
	if err != nil {
		return "", xurlErrors.NewAuthError("RequestCreationError", err)
	}

	req.Header.Add("Authorization", "Bearer "+accessToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", xurlErrors.NewAuthError("NetworkError", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", xurlErrors.NewAuthError("IOError", err)
	}

	var data map[string]any
	if err := json.Unmarshal(body, &data); err != nil {
		return "", xurlErrors.NewAuthError("JSONDeserializationError", err)
	}

	if data["data"] != nil {
		if userData, ok := data["data"].(map[string]any); ok {
			if username, ok := userData["username"].(string); ok {
				return username, nil
			}
		}
	}

	return "", xurlErrors.NewAuthError("UsernameNotFound", errors.New("username not found when fetching username"))
}

// OAuth1Flow runs the 3-legged OAuth1.0a authorization flow
func (a *Auth) OAuth1Flow() error {
	consumerKey := a.consumerKey
	consumerSecret := a.consumerSecret

	if consumerKey == "" || consumerSecret == "" {
		return xurlErrors.NewAuthError("MissingCredentials", errors.New("consumer key and consumer secret are required"))
	}

	callbackURL := a.redirectURI

	// Step 1: Get request token
	additionalParams := map[string]string{
		"oauth_callback": callbackURL,
	}

	authHeader, err := buildOAuth1AuthHeader("POST", a.oauth1RequestTokenURL, consumerKey, consumerSecret, "", "", additionalParams)
	if err != nil {
		return xurlErrors.NewAuthError("RequestTokenError", err)
	}

	req, err := http.NewRequest("POST", a.oauth1RequestTokenURL, nil)
	if err != nil {
		return xurlErrors.NewAuthError("RequestTokenError", err)
	}
	req.Header.Set("Authorization", authHeader)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return xurlErrors.NewAuthError("RequestTokenError", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return xurlErrors.NewAuthError("RequestTokenError", fmt.Errorf("request token failed with status %d: %s", resp.StatusCode, string(body)))
	}

	values, err := parseFormEncodedBody(resp)
	if err != nil {
		return xurlErrors.NewAuthError("RequestTokenError", err)
	}

	requestToken := values.Get("oauth_token")
	requestTokenSecret := values.Get("oauth_token_secret")

	if requestToken == "" || requestTokenSecret == "" {
		return xurlErrors.NewAuthError("RequestTokenError", errors.New("missing oauth_token or oauth_token_secret in response"))
	}

	// Step 2: Start listener before opening browser
	verifierChan := make(chan [2]string, 1)

	callback := func(oauthToken, oauthVerifier string) error {
		if oauthToken == "" || oauthVerifier == "" {
			return xurlErrors.NewAuthError("InvalidCallback", errors.New("missing oauth_token or oauth_verifier"))
		}
		verifierChan <- [2]string{oauthToken, oauthVerifier}
		return nil
	}

	parsedURL, err := url.Parse(callbackURL)
	if err != nil {
		return xurlErrors.NewAuthError("InvalidCallbackURL", err)
	}

	port := 8080
	if parsedURL.Port() != "" {
		fmt.Sscanf(parsedURL.Port(), "%d", &port)
	}

	listenerReady := make(chan struct{})
	go func() {
		if err := StartOAuth1Listener(port, callback, listenerReady); err != nil {
			fmt.Printf("Error in OAuth1 listener: %v\n", err)
		}
	}()

	// Wait for listener to be ready before opening browser
	<-listenerReady

	// Step 3: Direct user to authorize
	authorizeURL := fmt.Sprintf("%s?oauth_token=%s", a.oauth1AuthorizeURL, encode(requestToken))

	err = openBrowser(authorizeURL)
	if err != nil {
		fmt.Println("Failed to open browser automatically. Please visit this URL manually:")
		fmt.Println(authorizeURL)
	}

	var callbackToken, oauthVerifier string
	select {
	case result := <-verifierChan:
		callbackToken = result[0]
		oauthVerifier = result[1]
		_ = callbackToken
	case <-time.After(5 * time.Minute):
		return xurlErrors.NewAuthError("Timeout", errors.New("authentication timed out"))
	}

	// Step 4: Exchange for access token
	exchangeParams := map[string]string{
		"oauth_verifier": oauthVerifier,
	}

	exchangeHeader, err := buildOAuth1AuthHeader("POST", a.oauth1AccessTokenURL, consumerKey, consumerSecret, requestToken, requestTokenSecret, exchangeParams)
	if err != nil {
		return xurlErrors.NewAuthError("AccessTokenError", err)
	}

	exchangeReq, err := http.NewRequest("POST", a.oauth1AccessTokenURL, nil)
	if err != nil {
		return xurlErrors.NewAuthError("AccessTokenError", err)
	}
	exchangeReq.Header.Set("Authorization", exchangeHeader)

	exchangeResp, err := client.Do(exchangeReq)
	if err != nil {
		return xurlErrors.NewAuthError("AccessTokenError", err)
	}
	defer exchangeResp.Body.Close()

	if exchangeResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(exchangeResp.Body)
		return xurlErrors.NewAuthError("AccessTokenError", fmt.Errorf("access token exchange failed with status %d: %s", exchangeResp.StatusCode, string(body)))
	}

	accessValues, err := parseFormEncodedBody(exchangeResp)
	if err != nil {
		return xurlErrors.NewAuthError("AccessTokenError", err)
	}

	accessToken := accessValues.Get("oauth_token")
	accessTokenSecret := accessValues.Get("oauth_token_secret")

	if accessToken == "" || accessTokenSecret == "" {
		return xurlErrors.NewAuthError("AccessTokenError", errors.New("missing oauth_token or oauth_token_secret in access token response"))
	}

	// Step 5: Save tokens
	return a.TokenStore.SaveOAuth1Tokens(accessToken, accessTokenSecret, consumerKey, consumerSecret)
}

// parseFormEncodedBody reads and parses a form-encoded HTTP response body
func parseFormEncodedBody(resp *http.Response) (url.Values, error) {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, xurlErrors.NewAuthError("IOError", err)
	}
	values, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, xurlErrors.NewAuthError("ParseError", err)
	}
	return values, nil
}

func generateSignature(method, urlStr string, params map[string]string, consumerSecret, tokenSecret string) (string, error) {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return "", xurlErrors.NewAuthError("InvalidURL", err)
	}

	baseURL := fmt.Sprintf("%s://%s%s", parsedURL.Scheme, parsedURL.Host, parsedURL.Path)

	var keys []string
	for key := range params {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var paramPairs []string
	for _, key := range keys {
		paramPairs = append(paramPairs, fmt.Sprintf("%s=%s", encode(key), encode(params[key])))
	}
	paramString := strings.Join(paramPairs, "&")

	signatureBaseString := fmt.Sprintf("%s&%s&%s",
		strings.ToUpper(method),
		encode(baseURL),
		encode(paramString))

	signingKey := fmt.Sprintf("%s&%s", encode(consumerSecret), encode(tokenSecret))

	h := hmac.New(sha1.New, []byte(signingKey))
	h.Write([]byte(signatureBaseString))
	signature := base64.StdEncoding.EncodeToString(h.Sum(nil))

	return signature, nil
}

func generateNonce() string {
	n, _ := rand.Int(rand.Reader, big.NewInt(1000000000))
	return n.String()
}

func generateTimestamp() string {
	return fmt.Sprintf("%d", time.Now().Unix())
}

func encode(s string) string {
	return url.QueryEscape(s)
}

func generateCodeVerifierAndChallenge() (string, string) {
	b := make([]byte, 32)
	rand.Read(b)
	verifier := base64.RawURLEncoding.EncodeToString(b)
	h := sha256.New()
	h.Write([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	return verifier, challenge
}

func getOAuth2Scopes() []string {
	readScopes := []string{
		"tweet.read",
		"users.read",
		"bookmark.read",
		"follows.read",
		"list.read",
		"block.read",
		"mute.read",
		"like.read",
		"users.email",
		"dm.read",
	}

	writeScopes := []string{
		"tweet.write",
		"tweet.moderate.write",
		"follows.write",
		"bookmark.write",
		"block.write",
		"mute.write",
		"like.write",
		"list.write",
		"media.write",
		"dm.write",
	}

	otherScopes := []string{
		"offline.access",
		"space.read",
	}

	var scopes []string
	scopes = append(scopes, readScopes...)
	scopes = append(scopes, writeScopes...)
	scopes = append(scopes, otherScopes...)

	return scopes
}

func openBrowser(url string) error {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "windows":
		cmd = "cmd"
		args = []string{"/c", "start", url}
	case "darwin":
		cmd = "open"
		args = []string{url}
	default:
		cmd = "xdg-open"
		args = []string{url}
	}

	return exec.Command(cmd, args...).Start()
}
