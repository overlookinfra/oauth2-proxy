package providers

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/logger"

	"golang.org/x/oauth2"

	"github.com/coreos/go-oidc"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/requests"
)

var _ Provider = (*ProviderData)(nil)

// Redeem provides a default implementation of the OAuth2 token redemption process
func (p *ProviderData) Redeem(ctx context.Context, redirectURL, code string) (s *sessions.SessionState, err error) {
	if code == "" {
		err = errors.New("missing code")
		return
	}
	clientSecret, err := p.GetClientSecret()
	if err != nil {
		return
	}

	params := url.Values{}
	params.Add("redirect_uri", redirectURL)
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", clientSecret)
	params.Add("code", code)
	params.Add("grant_type", "authorization_code")
	if p.ProtectedResource != nil && p.ProtectedResource.String() != "" {
		params.Add("resource", p.ProtectedResource.String())
	}

	result := requests.New(p.RedeemURL.String()).
		WithContext(ctx).
		WithMethod("POST").
		WithBody(bytes.NewBufferString(params.Encode())).
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Do()
	if result.Error() != nil {
		return nil, result.Error()
	}

	// blindly try json and x-www-form-urlencoded
	var jsonResponse struct {
		AccessToken string `json:"access_token"`
	}
	err = result.UnmarshalInto(&jsonResponse)
	if err == nil {
		s = &sessions.SessionState{
			AccessToken: jsonResponse.AccessToken,
		}
		return
	}

	var v url.Values
	v, err = url.ParseQuery(string(result.Body()))
	if err != nil {
		return
	}
	if a := v.Get("access_token"); a != "" {
		created := time.Now()
		s = &sessions.SessionState{AccessToken: a, CreatedAt: &created}
	} else {
		err = fmt.Errorf("no access token found %s", result.Body())
	}
	return
}

// GetLoginURL with typical oauth parameters
func (p *ProviderData) GetLoginURL(redirectURI, state string) string {
	a := *p.LoginURL
	params, _ := url.ParseQuery(a.RawQuery)
	params.Set("redirect_uri", redirectURI)
	if p.AcrValues != "" {
		params.Add("acr_values", p.AcrValues)
	}
	if p.Prompt != "" {
		params.Set("prompt", p.Prompt)
	} else { // Legacy variant of the prompt param:
		params.Set("approval_prompt", p.ApprovalPrompt)
	}
	params.Add("scope", p.Scope)
	params.Set("client_id", p.ClientID)
	params.Set("response_type", "code")
	params.Add("state", state)
	a.RawQuery = params.Encode()
	return a.String()
}

// GetOfflineToken with typical oauth parameters
func (p *ProviderData) GetOfflineToken(username string, password string) (string, int) {
	params := url.Values{}
	params.Add("scope", "offline_access")
	params.Add("client_id", p.ClientID)
	params.Add("username", username)
	params.Add("password", password)
	params.Add("grant_type", "password")
	params.Add("client_secret", p.ClientSecret)

	var token oauth2.Token
	result := requests.New(p.RedeemURL.String()).
		WithMethod("POST").
		WithBody(bytes.NewBufferString(params.Encode())).
		SetHeader("Content-Type", "application/x-www-form-urlencoded").Do()

	if result.Error() != nil || result.StatusCode() != http.StatusOK {
		logger.Errorf("Error retrieving offline token %s. Status code %d", result.Error(), result.StatusCode())
		responseCode := http.StatusInternalServerError
		if result.StatusCode() != http.StatusOK {
			responseCode = result.StatusCode()
		}
		return "", responseCode
	}

	result.UnmarshalInto(&token)
	return token.RefreshToken, http.StatusOK
}

// GetEmailAddress returns the Account email address
func (p *ProviderData) GetEmailAddress(ctx context.Context, s *sessions.SessionState) (string, error) {
	return "", errors.New("not implemented")
}

// GetUserName returns the Account username
func (p *ProviderData) GetUserName(ctx context.Context, s *sessions.SessionState) (string, error) {
	return "", errors.New("not implemented")
}

// GetPreferredUsername returns the Account preferred username
func (p *ProviderData) GetPreferredUsername(ctx context.Context, s *sessions.SessionState) (string, error) {
	return "", errors.New("not implemented")
}

// ValidateGroup validates that the provided email exists in the configured provider
// email group(s).
func (p *ProviderData) ValidateGroup(email string) bool {
	return true
}

// ValidateSessionState validates the AccessToken
func (p *ProviderData) ValidateSessionState(ctx context.Context, s *sessions.SessionState) bool {
	return validateToken(ctx, p, s.AccessToken, nil)
}

// RefreshSessionIfNeeded should refresh the user's session if required and
// do nothing if a refresh is not required
func (p *ProviderData) RefreshSessionIfNeeded(ctx context.Context, s *sessions.SessionState) (bool, error) {
	return false, nil
}

// CreateSessionStateFromBearerToken should be implemented to allow providers
// to convert ID tokens into sessions
func (p *ProviderData) CreateSessionStateFromBearerToken(ctx context.Context, rawIDToken string, idToken *oidc.IDToken) (*sessions.SessionState, error) {
	return nil, errors.New("not implemented")
}

// GetAccessTokenFromRefreshToken with a context and refresh token
func (p *ProviderData) GetAccessTokenFromRefreshToken(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
	clientSecret, err := p.GetClientSecret()
	if err != nil {
		return nil, err
	}

	c := oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: clientSecret,
		Endpoint: oauth2.Endpoint{
			TokenURL: p.RedeemURL.String(),
		},
	}
	t := &oauth2.Token{
		RefreshToken: refreshToken,
		Expiry:       time.Now().Add(-time.Hour),
	}
	token, err := c.TokenSource(ctx, t).Token()
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %v", err)
	}

	return token, nil
}
