package device

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dexidp/dex/server/oauth2"
	"github.com/dexidp/dex/storage"
	"github.com/dexidp/dex/storage/memory"
)

func TestGetDeviceVerificationURI(t *testing.T) {
	u, err := url.Parse("https://dex.example.com/non-root-path")
	require.NoError(t, err)

	h := &Handler{IssuerURL: oauth2.IssuerURL{URL: *u}}
	require.Equal(t, "/non-root-path/device/auth/verify_code", h.getDeviceVerificationURI())
}

// TestCreateDeviceAuthorizationUsesInjectedClock pins the device request and
// token expiry to the handler's clock. Both were minted from a mix of
// time.Now() and h.Now(), which made the two expiries drift apart under a
// fixed test clock.
func TestCreateDeviceAuthorizationUsesInjectedClock(t *testing.T) {
	u, err := url.Parse("https://dex.example.com")
	require.NoError(t, err)

	fixed := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	h := &Handler{
		IssuerURL:        oauth2.IssuerURL{URL: *u},
		Storage:          memory.New(logger),
		Logger:           logger,
		Now:              func() time.Time { return fixed },
		RequestsValidFor: 5 * time.Minute,
	}

	resp, ferr := h.createDeviceAuthorization(t.Context(), deviceCodeRequest{
		clientID: "test",
		scopes:   []string{"openid"},
	})
	require.Nil(t, ferr)

	want := fixed.Add(5 * time.Minute)

	req, err := h.Storage.GetDeviceRequest(t.Context(), resp.UserCode)
	require.NoError(t, err)
	require.WithinDuration(t, want, req.Expiry, 0)

	token, err := h.Storage.GetDeviceToken(t.Context(), resp.DeviceCode)
	require.NoError(t, err)
	require.WithinDuration(t, want, token.Expiry, 0)
	require.WithinDuration(t, fixed, token.LastRequestTime, 0)
}

// TestHandleDeviceCodeClientAuthentication ensures /device/code authenticates
// the client before minting anything: an absent or unknown client or a bad
// secret is rejected, Basic credentials are honored, and valid credentials still
// receive a device code bound to the authenticated client.
func TestHandleDeviceCodeClientAuthentication(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	fixed := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

	newHandler := func(t *testing.T) *Handler {
		t.Helper()
		u, err := url.Parse("https://dex.example.com")
		require.NoError(t, err)

		s := memory.New(logger)
		require.NoError(t, s.CreateClient(t.Context(), storage.Client{ID: "conf", Secret: "s3cret"}))
		require.NoError(t, s.CreateClient(t.Context(), storage.Client{ID: "public"}))

		return &Handler{
			IssuerURL:        oauth2.IssuerURL{URL: *u},
			Storage:          s,
			Logger:           logger,
			Now:              func() time.Time { return fixed },
			RequestsValidFor: 5 * time.Minute,
		}
	}

	tests := []struct {
		name         string
		query        string
		form         url.Values
		basicID      string
		basicSecret  string
		wantStatus   int
		wantClientID string
	}{
		{"missing client", "", nil, "", "", http.StatusUnauthorized, ""},
		{"unknown client", "", url.Values{"client_id": {"nope"}}, "", "", http.StatusUnauthorized, ""},
		{"wrong secret in form", "", url.Values{"client_id": {"conf"}, "client_secret": {"wrong"}}, "", "", http.StatusUnauthorized, ""},
		{"wrong secret in basic auth", "", nil, "conf", "wrong", http.StatusUnauthorized, ""},
		{"basic auth wins over form", "", url.Values{"client_id": {"conf"}, "client_secret": {"s3cret"}}, "conf", "wrong", http.StatusUnauthorized, ""},
		{"query credentials are not the form credentials", "?client_id=conf", nil, "", "", http.StatusUnauthorized, ""},
		{"public client without a secret", "", url.Values{"client_id": {"public"}}, "", "", http.StatusOK, "public"},
		{"public client with a secret", "", url.Values{"client_id": {"public"}, "client_secret": {"wrong"}}, "", "", http.StatusUnauthorized, ""},
		{"secret in form", "", url.Values{"client_id": {"conf"}, "client_secret": {"s3cret"}}, "", "", http.StatusOK, "conf"},
		{"secret in basic auth", "", nil, "conf", "s3cret", http.StatusOK, "conf"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHandler(t)

			req := httptest.NewRequest(http.MethodPost, "https://dex.example.com/device/code"+tc.query, strings.NewReader(tc.form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if tc.basicID != "" {
				req.SetBasicAuth(tc.basicID, tc.basicSecret)
			}
			rr := httptest.NewRecorder()
			h.handleDeviceCode(rr, req)

			require.Equal(t, tc.wantStatus, rr.Code, rr.Body.String())
			if tc.wantClientID == "" {
				var errResp struct {
					Error string `json:"error"`
				}
				require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &errResp))
				require.Equal(t, oauth2.InvalidClient, errResp.Error)
				return
			}

			var resp DeviceCodeResponse
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
			deviceReq, err := h.Storage.GetDeviceRequest(t.Context(), resp.UserCode)
			require.NoError(t, err)
			require.Equal(t, tc.wantClientID, deviceReq.ClientID)
		})
	}
}
