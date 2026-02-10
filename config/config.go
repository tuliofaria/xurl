package config

import (
	"fmt"
	"os"
)

// Config holds the application configuration
type Config struct {
	// OAuth2 client tokens
	ClientID     string
	ClientSecret string
	// OAuth2 PKCE flow urls
	RedirectURI string
	AuthURL     string
	TokenURL    string
	// OAuth1 consumer tokens
	ConsumerKey    string
	ConsumerSecret string
	// OAuth1 3-legged flow urls
	OAuth1RequestTokenURL string
	OAuth1AuthorizeURL    string
	OAuth1AccessTokenURL  string
	// API base url
	APIBaseURL string
	// API user info url
	InfoURL string
}

// NewConfig creates a new Config from environment variables
func NewConfig() *Config {
	clientID := getEnvOrDefault("CLIENT_ID", "")
	clientSecret := getEnvOrDefault("CLIENT_SECRET", "")
	redirectURI := getEnvOrDefault("REDIRECT_URI", "http://localhost:8080/callback")
	authURL := getEnvOrDefault("AUTH_URL", "https://x.com/i/oauth2/authorize")
	tokenURL := getEnvOrDefault("TOKEN_URL", "https://api.x.com/2/oauth2/token")
	consumerKey := getEnvOrDefault("CONSUMER_KEY", "")
	consumerSecret := getEnvOrDefault("CONSUMER_SECRET", "")
	oauth1RequestTokenURL := getEnvOrDefault("OAUTH1_REQUEST_TOKEN_URL", "https://api.x.com/oauth/request_token")
	oauth1AuthorizeURL := getEnvOrDefault("OAUTH1_AUTHORIZE_URL", "https://api.x.com/oauth/authorize")
	oauth1AccessTokenURL := getEnvOrDefault("OAUTH1_ACCESS_TOKEN_URL", "https://api.x.com/oauth/access_token")
	apiBaseURL := getEnvOrDefault("API_BASE_URL", "https://api.x.com")
	infoURL := getEnvOrDefault("INFO_URL", fmt.Sprintf("%s/2/users/me", apiBaseURL))

	return &Config{
		ClientID:              clientID,
		ClientSecret:          clientSecret,
		RedirectURI:           redirectURI,
		AuthURL:               authURL,
		TokenURL:              tokenURL,
		ConsumerKey:           consumerKey,
		ConsumerSecret:        consumerSecret,
		OAuth1RequestTokenURL: oauth1RequestTokenURL,
		OAuth1AuthorizeURL:    oauth1AuthorizeURL,
		OAuth1AccessTokenURL:  oauth1AccessTokenURL,
		APIBaseURL:            apiBaseURL,
		InfoURL:               infoURL,
	}
}

// Helper function to get environment variable with default value
func getEnvOrDefault(key, defaultValue string) string {
	value, exists := os.LookupEnv(key)
	if !exists {
		return defaultValue
	}
	return value
}
