package auth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	xurlErrors "xurl/errors"
)

func StartListener(port int, callback func(code, state string) error) error {
	mux := http.NewServeMux()

	server := &http.Server{
		Handler: mux,
	}

	done := make(chan error, 1)

	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")

		err := callback(code, state)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "Error: %s", err.Error())
			done <- err
			return
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Authentication successful! You can close this window.")

		done <- nil

		go func() {
			server.Shutdown(context.Background())
		}()
	})

	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return xurlErrors.NewAuthError("ServerError", err)
	}

	go func() {
		if err := server.Serve(ln); err != nil && err != http.ErrServerClosed {
			done <- xurlErrors.NewAuthError("ServerError", err)
		}
	}()

	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Minute):
		server.Shutdown(context.Background())
		return xurlErrors.NewAuthError("Timeout", errors.New("timeout waiting for callback"))
	}
}

// StartOAuth1Listener starts a listener for OAuth1 callbacks.
// It extracts oauth_token and oauth_verifier from the callback query params.
// The ready channel is closed once the server is listening and ready to accept connections.
func StartOAuth1Listener(port int, callback func(oauthToken, oauthVerifier string) error, ready chan<- struct{}) error {
	mux := http.NewServeMux()

	server := &http.Server{
		Handler: mux,
	}

	done := make(chan error, 1)

	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		denied := r.URL.Query().Get("denied")
		if denied != "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "Authorization was denied.")
			done <- xurlErrors.NewAuthError("AuthorizationDenied", errors.New("user denied authorization"))
			go func() {
				server.Shutdown(context.Background())
			}()
			return
		}

		oauthToken := r.URL.Query().Get("oauth_token")
		oauthVerifier := r.URL.Query().Get("oauth_verifier")

		err := callback(oauthToken, oauthVerifier)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "Error: %s", err.Error())
			done <- err
			return
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Authentication successful! You can close this window.")

		done <- nil

		go func() {
			server.Shutdown(context.Background())
		}()
	})

	// Bind on all interfaces so localhost works regardless of IPv4/IPv6 resolution
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		close(ready)
		return xurlErrors.NewAuthError("ServerError", err)
	}

	close(ready)

	go func() {
		if err := server.Serve(ln); err != nil && err != http.ErrServerClosed {
			done <- xurlErrors.NewAuthError("ServerError", err)
		}
	}()

	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Minute):
		server.Shutdown(context.Background())
		return xurlErrors.NewAuthError("Timeout", errors.New("timeout waiting for callback"))
	}
}
