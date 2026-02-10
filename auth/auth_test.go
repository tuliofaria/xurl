package auth

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"xurl/config"
	"xurl/store"
)

// Helper function to create a temporary token store for testing
func createTempTokenStore(t *testing.T) (*store.TokenStore, string) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "xurl_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	// Create a token store with a file in the temp directory
	tempFile := filepath.Join(tempDir, "tokens.json")
	store := &store.TokenStore{
		OAuth2Tokens: make(map[string]store.Token),
		FilePath:     tempFile,
	}

	return store, tempDir
}

func TestNewAuth(t *testing.T) {
	cfg := &config.Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURI:  "http://localhost:8080/callback",
		AuthURL:      "https://x.com/i/oauth2/authorize",
		TokenURL:     "https://api.x.com/2/oauth2/token",
		APIBaseURL:   "https://api.x.com",
		InfoURL:      "https://api.x.com/2/users/me",
	}

	auth := NewAuth(cfg)

	require.NotNil(t, auth, "Expected non-nil Auth")
	assert.NotNil(t, auth.TokenStore, "Expected non-nil TokenStore")
}

func TestWithTokenStore(t *testing.T) {
	cfg := &config.Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURI:  "http://localhost:8080/callback",
		AuthURL:      "https://x.com/i/oauth2/authorize",
		TokenURL:     "https://api.x.com/2/oauth2/token",
		APIBaseURL:   "https://api.x.com",
		InfoURL:      "https://api.x.com/2/users/me",
	}

	auth := NewAuth(cfg)

	tokenStore, tempDir := createTempTokenStore(t)
	defer os.RemoveAll(tempDir)

	newAuth := auth.WithTokenStore(tokenStore)

	require.NotNil(t, newAuth, "Expected non-nil Auth")
	assert.Equal(t, tokenStore, newAuth.TokenStore, "Expected TokenStore to be set to the provided TokenStore")
}

func TestBearerToken(t *testing.T) {
	cfg := &config.Config{}

	auth := NewAuth(cfg)
	tokenStore, tempDir := createTempTokenStore(t)
	defer os.RemoveAll(tempDir)

	auth = auth.WithTokenStore(tokenStore)

	// Test with no bearer token
	_, err := auth.GetBearerTokenHeader()
	assert.Error(t, err, "Expected error when no bearer token is set")

	// Test with bearer token
	err = tokenStore.SaveBearerToken("test-bearer-token")
	require.NoError(t, err, "Failed to save bearer token")

	token, err := auth.GetBearerTokenHeader()
	require.NoError(t, err, "Failed to get bearer token")
	assert.Equal(t, "Bearer test-bearer-token", token, "Expected correct bearer token format")
}

func TestGenerateNonce(t *testing.T) {
	nonce1 := generateNonce()
	nonce2 := generateNonce()

	assert.NotEmpty(t, nonce1, "Expected non-empty nonce")
	assert.NotEqual(t, nonce1, nonce2, "Expected different nonces")
}

func TestGenerateTimestamp(t *testing.T) {
	timestamp := generateTimestamp()

	assert.NotEmpty(t, timestamp, "Expected non-empty timestamp")

	for _, c := range timestamp {
		assert.True(t, c >= '0' && c <= '9', "Expected timestamp to contain only digits, got %s", timestamp)
	}
}

func TestEncode(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
	}{
		{"abc", "abc"},
		{"a b c", "a+b+c"},
		{"a+b+c", "a%2Bb%2Bc"},
		{"a/b/c", "a%2Fb%2Fc"},
		{"a?b=c", "a%3Fb%3Dc"},
		{"a&b=c", "a%26b%3Dc"},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result := encode(tc.input)
			assert.Equal(t, tc.expected, result, "encode(%q) should return %q", tc.input, result)
		})
	}
}

func TestGenerateCodeVerifierAndChallenge(t *testing.T) {
	verifier, challenge := generateCodeVerifierAndChallenge()

	assert.NotEmpty(t, verifier, "Expected non-empty verifier")
	assert.NotEmpty(t, challenge, "Expected non-empty challenge")
	assert.NotEqual(t, verifier, challenge, "Expected verifier and challenge to be different")
}

func TestGetOAuth2Scopes(t *testing.T) {
	scopes := getOAuth2Scopes()

	assert.NotEmpty(t, scopes, "Expected non-empty scopes")

	// Check for some common scopes
	assert.Contains(t, scopes, "tweet.read", "Expected 'tweet.read' scope")
	assert.Contains(t, scopes, "users.read", "Expected 'users.read' scope")
}

func TestBuildOAuth1AuthHeaderWithToken(t *testing.T) {
	header, err := buildOAuth1AuthHeader(
		"GET",
		"https://api.x.com/2/users/me",
		"consumer-key",
		"consumer-secret",
		"access-token",
		"token-secret",
		nil,
	)

	require.NoError(t, err)
	assert.Contains(t, header, "OAuth ")
	assert.Contains(t, header, "oauth_consumer_key=\"consumer-key\"")
	assert.Contains(t, header, "oauth_token=\"access-token\"")
	assert.Contains(t, header, "oauth_signature_method=\"HMAC-SHA1\"")
	assert.Contains(t, header, "oauth_version=\"1.0\"")
	assert.Contains(t, header, "oauth_signature=")
	assert.Contains(t, header, "oauth_nonce=")
	assert.Contains(t, header, "oauth_timestamp=")
}

func TestBuildOAuth1AuthHeaderWithoutToken(t *testing.T) {
	header, err := buildOAuth1AuthHeader(
		"POST",
		"https://api.x.com/oauth/request_token",
		"consumer-key",
		"consumer-secret",
		"",
		"",
		map[string]string{
			"oauth_callback": "http://localhost:8080/callback",
		},
	)

	require.NoError(t, err)
	assert.Contains(t, header, "OAuth ")
	assert.Contains(t, header, "oauth_consumer_key=\"consumer-key\"")
	assert.NotContains(t, header, "oauth_token=")
	assert.Contains(t, header, "oauth_callback=")
	assert.Contains(t, header, "oauth_signature=")
}

func TestSetConsumerCredentials(t *testing.T) {
	cfg := &config.Config{}
	a := NewAuth(cfg)

	a.SetConsumerCredentials("my-key", "my-secret")
	assert.Equal(t, "my-key", a.consumerKey)
	assert.Equal(t, "my-secret", a.consumerSecret)
}

func TestStartListenerDoesNotPanic(t *testing.T) {
	// Verify that StartListener uses a new mux and doesn't panic
	// when called multiple times (the DefaultServeMux bug fix)
	done := make(chan error, 1)

	go func() {
		err := StartListener(18931, func(code, state string) error {
			return nil
		})
		done <- err
	}()

	// Give the server a moment to start, then make a request to unblock it
	<-time.After(100 * time.Millisecond)

	resp, err := http.Get("http://127.0.0.1:18931/callback?code=test&state=test")
	if err == nil {
		resp.Body.Close()
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("StartListener timed out")
	}

	// Call it again - this would panic with DefaultServeMux
	go func() {
		err := StartListener(18931, func(code, state string) error {
			return nil
		})
		done <- err
	}()

	<-time.After(100 * time.Millisecond)

	resp, err = http.Get("http://127.0.0.1:18931/callback?code=test2&state=test2")
	if err == nil {
		resp.Body.Close()
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Second StartListener call timed out")
	}
}

func TestStartOAuth1Listener(t *testing.T) {
	done := make(chan error, 1)
	resultChan := make(chan [2]string, 1)
	ready := make(chan struct{})

	go func() {
		err := StartOAuth1Listener(18932, func(oauthToken, oauthVerifier string) error {
			resultChan <- [2]string{oauthToken, oauthVerifier}
			return nil
		}, ready)
		done <- err
	}()

	<-ready

	resp, err := http.Get("http://127.0.0.1:18932/callback?oauth_token=req-token&oauth_verifier=verifier-123")
	require.NoError(t, err)
	resp.Body.Close()

	select {
	case result := <-resultChan:
		assert.Equal(t, "req-token", result[0])
		assert.Equal(t, "verifier-123", result[1])
	case <-time.After(2 * time.Second):
		t.Fatal("OAuth1 listener did not receive callback")
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("StartOAuth1Listener timed out")
	}
}

func TestStartOAuth1ListenerDenied(t *testing.T) {
	done := make(chan error, 1)
	ready := make(chan struct{})

	go func() {
		err := StartOAuth1Listener(18933, func(oauthToken, oauthVerifier string) error {
			t.Fatal("Callback should not be called when authorization is denied")
			return nil
		}, ready)
		done <- err
	}()

	<-ready

	resp, err := http.Get("http://127.0.0.1:18933/callback?denied=some-token")
	require.NoError(t, err)
	resp.Body.Close()

	select {
	case err := <-done:
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "denied")
	case <-time.After(2 * time.Second):
		t.Fatal("StartOAuth1Listener did not return after denied")
	}
}
