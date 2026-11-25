package authflow

import (
	"crypto"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dexidp/dex/server/internal"
	"github.com/dexidp/dex/storage"
)

func hardeningTestCookieRequest(sessionID, secret string) *http.Request {
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{
		Name:  "dex_session",
		Value: internal.SessionCookieValue(sessionID, secret, nil),
	})
	return r
}

func TestSupersededCookieCannotExtendTokenActivity(t *testing.T) {
	ctx := t.Context()
	s := newTestSessionServer(t)
	now := s.Now()

	oldActivity := now.Add(-10 * time.Minute)
	oldExpiry := now.Add(50 * time.Minute)
	require.NoError(t, s.Storage.CreateAuthSession(ctx, storage.AuthSession{
		ID: "session-1", Secret: "new-secret", UserID: "user-1", ConnectorID: "mock",
		ClientStates: map[string]*storage.ClientAuthState{
			"client-1": {AuthenticatedAt: now.Add(-time.Hour), LastActivity: oldActivity},
		},
		CreatedAt:      now.Add(-time.Hour),
		LastActivity:   oldActivity,
		AbsoluteExpiry: now.Add(24 * time.Hour),
		IdleExpiry:     oldExpiry,
	}))

	s.Sessions.UpdateTokenIssuedAt(hardeningTestCookieRequest("session-1", "old-secret"), "client-1")

	got, err := s.Storage.GetAuthSession(ctx, "session-1")
	require.NoError(t, err)
	require.Equal(t, oldActivity, got.LastActivity)
	require.Equal(t, oldExpiry, got.IdleExpiry)
	require.Equal(t, oldActivity, got.ClientStates["client-1"].LastActivity)
}

func TestRotatedCookieCannotExtendSessionLoginTouch(t *testing.T) {
	ctx := t.Context()
	s := newTestSessionServer(t)
	now := s.Now()

	oldActivity := now.Add(-10 * time.Minute)
	oldExpiry := now.Add(50 * time.Minute)
	require.NoError(t, s.Storage.CreateAuthSession(ctx, storage.AuthSession{
		ID: "test-nonce", Secret: "old-secret", UserID: "user-1", ConnectorID: "mock",
		ClientStates: map[string]*storage.ClientAuthState{
			"client-1": {AuthenticatedAt: now.Add(-time.Minute), LastActivity: oldActivity},
		},
		CreatedAt:      now.Add(-30 * time.Minute),
		LastActivity:   oldActivity,
		AbsoluteExpiry: now.Add(24 * time.Hour),
		IdleExpiry:     oldExpiry,
	}))
	require.NoError(t, s.Storage.CreateUserIdentity(ctx, storage.UserIdentity{
		UserID: "user-1", ConnectorID: "mock",
		Claims:    storage.Claims{UserID: "user-1", Username: "testuser", Email: "test@example.com"},
		Consents:  map[string][]string{},
		CreatedAt: now.Add(-time.Hour), LastLogin: now.Add(-30 * time.Minute),
	}))

	authReq := storage.AuthRequest{
		ID: storage.NewID(), ClientID: "client-1", ConnectorID: "mock",
		Scopes: []string{"openid"}, RedirectURI: "http://localhost/callback",
		MaxAge: -1, HMACKey: storage.NewHMACKey(crypto.SHA256), Expiry: now.Add(10 * time.Minute),
	}
	require.NoError(t, s.Storage.CreateAuthRequest(ctx, authReq))

	r := hardeningTestCookieRequest("test-nonce", "old-secret")
	session := s.Sessions.ValidAuthSession(ctx, httptest.NewRecorder(), r, &authReq)
	require.NotNil(t, session)

	// The browser receives a replacement cookie/secret after this request's
	// initial validation. The stale request must not be allowed to touch the
	// current record.
	require.NoError(t, s.Storage.UpdateAuthSession(ctx, "test-nonce", func(old storage.AuthSession) (storage.AuthSession, error) {
		old.Secret = "new-secret"
		return old, nil
	}))

	ok := s.trySessionLoginWithSession(ctx, r, httptest.NewRecorder(), &authReq, session)
	require.False(t, ok, "a superseded cookie must not complete session login")

	got, err := s.Storage.GetAuthSession(ctx, "test-nonce")
	require.NoError(t, err)
	require.Equal(t, "new-secret", got.Secret)
	require.Equal(t, oldActivity, got.LastActivity)
	require.Equal(t, oldExpiry, got.IdleExpiry)
	require.Equal(t, oldActivity, got.ClientStates["client-1"].LastActivity)
}
