package middleware

import (
	"context"
	"fmt"
	"net/http"

	"github.com/oauth2-proxy/oauth2-proxy/providers"

	"github.com/justinas/alice"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/logger"
)

func NewAccessTokenFromRefreshToken(provider providers.Provider) alice.Constructor {
	return func(next http.Handler) http.Handler {
		return loadAccessTokenFromRefreshToken(provider, next)
	}
}

// loadAccessTokenFromRefreshToken attmepts to load a session from an offline refresh token
func loadAccessTokenFromRefreshToken(provider providers.Provider, next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		scope := GetRequestScope(req)
		// If scope is nil, this will panic.
		// A scope should always be injected before this handler is called.
		if scope.Session != nil {
			// The session was already loaded, pass to the next handler
			next.ServeHTTP(rw, req)
			return
		}

		err := setAccessToken(provider, req)
		if err != nil {
			logger.Errorf("Error retrieving session from token in Authorization header: %v", err)
		}

		// Add the session to the scope if it was found
		next.ServeHTTP(rw, req)
	})
}

// setAccessToken attempts to load a session based on the refresh token passed through in the header
func setAccessToken(provider providers.Provider, req *http.Request) error {
	auth := req.Header.Get("X-Auth-Offline-Refresh-Token")
	if auth == "" {
		// No auth header provided, so don't attempt to load a session
		return nil
	}

	token, err := provider.GetAccessTokenFromRefreshToken(context.Background(), auth)
	if err != nil {
		return err
	}

	if token != nil {
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token.AccessToken))
	}
	return nil
}
