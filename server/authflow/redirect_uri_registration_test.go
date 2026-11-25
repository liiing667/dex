package authflow

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dexidp/dex/server/oauth2"
	"github.com/dexidp/dex/storage"
	"github.com/dexidp/dex/storage/memory"
)

// newRedirectTestHandler builds just enough of a Handler to exercise
// parseAuthorizationRequest without starting an HTTP listener.
func newRedirectTestHandler(t *testing.T, client storage.Client) *Handler {
	t.Helper()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return &Handler{
		IssuerURL: oauth2.IssuerURL{
			URL: url.URL{Scheme: "https", Host: "dex.example.com", Path: "/dex"},
		},
		Storage:                storage.WithStaticClients(memory.New(logger), []storage.Client{client}),
		Logger:                 logger,
		SupportedResponseTypes: map[string]bool{oauth2.ResponseTypeCode: true},
		PKCE: PKCEConfig{
			CodeChallengeMethodsSupported: []string{oauth2.PKCEMethodPlain, oauth2.PKCEMethodS256},
		},
	}
}

func parseRedirectURI(t *testing.T, h *Handler, clientID, redirectURI string) (*storage.AuthRequest, error) {
	t.Helper()

	params := url.Values{
		"client_id":     {clientID},
		"redirect_uri":  {redirectURI},
		"response_type": {oauth2.ResponseTypeCode},
		"scope":         {"openid"},
		"state":         {"state"},
	}
	req := httptest.NewRequest(http.MethodGet, "/dex/auth?"+params.Encode(), nil)
	authReq, _, err := h.parseAuthorizationRequest(req)
	return authReq, err
}

// TestParseAuthorizationRequestRejectsUnregisteredSpecialRedirects pins the
// invariant that a public client which registered its own redirect URIs cannot
// fall back to the implicit localhost/oob/device redirects. Those implicit
// redirects are only for public clients that registered no URIs at all.
func TestParseAuthorizationRequestRejectsUnregisteredSpecialRedirects(t *testing.T) {
	const clientID = "public-web"
	h := newRedirectTestHandler(t, storage.Client{
		ID:           clientID,
		Public:       true,
		RedirectURIs: []string{"https://app.example.com/callback"},
	})

	for _, redirectURI := range []string{
		"http://localhost:8080/",
		"http://127.0.0.1:991/bar",
		"http://localhost",
		oauth2.RedirectURIOOB,
		oauth2.DeviceCallbackURI,
		h.IssuerURL.AbsPath(oauth2.DeviceCallbackURI),
	} {
		t.Run(redirectURI, func(t *testing.T) {
			_, err := parseRedirectURI(t, h, clientID, redirectURI)
			var displayed *displayedAuthErr
			require.Error(t, err)
			require.True(t, errors.As(err, &displayed), "want displayedAuthErr, got %T", err)
			assert.Equal(t, http.StatusBadRequest, displayed.Status)
			assert.Contains(t, displayed.Error(), "Unregistered redirect_uri")
		})
	}
}

// TestParseAuthorizationRequestAcceptsRegisteredRedirects makes sure enforcing
// the registered set does not break clients that explicitly registered an
// ordinary or a special redirect URI.
func TestParseAuthorizationRequestAcceptsRegisteredRedirects(t *testing.T) {
	tests := []struct {
		name         string
		redirectURI  string
		wantRedirect string
	}{
		{
			name:         "ordinary URI",
			redirectURI:  "https://app.example.com/callback",
			wantRedirect: "https://app.example.com/callback",
		},
		{
			name:         "localhost",
			redirectURI:  "http://localhost:8080/",
			wantRedirect: "http://localhost:8080/",
		},
		{
			name:         "loopback IP",
			redirectURI:  "http://127.0.0.1:991/bar",
			wantRedirect: "http://127.0.0.1:991/bar",
		},
		{
			name:         "out of band",
			redirectURI:  oauth2.RedirectURIOOB,
			wantRedirect: oauth2.RedirectURIOOB,
		},
		{
			name:         "device callback under issuer path",
			redirectURI:  "/dex/device/callback",
			wantRedirect: "/dex/device/callback",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			const clientID = "registered"
			h := newRedirectTestHandler(t, storage.Client{
				ID:           clientID,
				Public:       true,
				RedirectURIs: []string{tc.redirectURI},
			})

			authReq, err := parseRedirectURI(t, h, clientID, tc.redirectURI)
			require.NoError(t, err)
			assert.Equal(t, tc.wantRedirect, authReq.RedirectURI)
		})
	}
}

// TestParseAuthorizationRequestKeepsImplicitRedirectsWithoutRegistration keeps
// the legacy native-client behavior for public clients that registered no
// redirect URIs.
func TestParseAuthorizationRequestKeepsImplicitRedirectsWithoutRegistration(t *testing.T) {
	tests := []struct {
		name         string
		redirectURI  string
		wantRedirect string
	}{
		{
			name:         "localhost",
			redirectURI:  "http://localhost:8080/",
			wantRedirect: "http://localhost:8080/",
		},
		{
			name:         "loopback IP",
			redirectURI:  "http://127.0.0.1:991/bar",
			wantRedirect: "http://127.0.0.1:991/bar",
		},
		{
			name:         "out of band",
			redirectURI:  oauth2.RedirectURIOOB,
			wantRedirect: oauth2.RedirectURIOOB,
		},
		{
			name:         "bare device callback is rewritten under the issuer path",
			redirectURI:  oauth2.DeviceCallbackURI,
			wantRedirect: "/dex/device/callback",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			const clientID = "native"
			h := newRedirectTestHandler(t, storage.Client{ID: clientID, Public: true})

			authReq, err := parseRedirectURI(t, h, clientID, tc.redirectURI)
			require.NoError(t, err)
			assert.Equal(t, tc.wantRedirect, authReq.RedirectURI)
		})
	}
}
