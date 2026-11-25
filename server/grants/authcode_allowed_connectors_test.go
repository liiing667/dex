package grants

import (
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dexidp/dex/server/connectors"
	"github.com/dexidp/dex/server/oauth2"
	"github.com/dexidp/dex/storage"
	"github.com/dexidp/dex/storage/memory"
)

func TestExchangeAuthCodeRejectsDisallowedConnectorBeforeConsumption(t *testing.T) {
	ctx := t.Context()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := memory.New(logger)

	client := storage.Client{
		ID:                "client-id",
		AllowedConnectors: []string{"allowed-connector"},
	}
	authCode := storage.AuthCode{
		ID:          "auth-code-id",
		ClientID:    client.ID,
		ConnectorID: "other-connector",
		Expiry:      time.Now().Add(time.Minute),
	}
	require.NoError(t, store.CreateAuthCode(ctx, authCode))

	_, _, err := ExchangeAuthCode(ctx, store, nil, logger, authCode, client)

	var oauthErr *oauth2.Error
	require.ErrorAs(t, err, &oauthErr)
	require.Equal(t, oauth2.InvalidGrant, oauthErr.Type)
	require.Equal(t, http.StatusBadRequest, oauthErr.Status)
	require.Contains(t, oauthErr.Description, "Connector not allowed")

	storedCode, getErr := store.GetAuthCode(ctx, authCode.ID)
	require.NoError(t, getErr)
	require.Equal(t, authCode.ID, storedCode.ID)
}

func TestExchangeAuthCodeAllowsPermittedConnectorPolicies(t *testing.T) {
	for _, tc := range []struct {
		name              string
		allowedConnectors []string
	}{
		{name: "explicitly allowed", allowedConnectors: []string{"some-other", "permitted-connector"}},
		{name: "unconfigured list permits all", allowedConnectors: nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			logger := slog.New(slog.NewTextHandler(io.Discard, nil))
			store := memory.New(logger)

			const connectorID = "permitted-connector"
			client := storage.Client{ID: "client-id", AllowedConnectors: tc.allowedConnectors}
			require.NoError(t, store.CreateConnector(ctx, storage.Connector{ID: connectorID}))
			connCache := connectors.NewCache(store, nil)
			connCache.Set(connectorID, connectors.Connector{})

			authCode := storage.AuthCode{
				ID:          "auth-code-id",
				ClientID:    client.ID,
				ConnectorID: connectorID,
				Expiry:      time.Now().Add(time.Minute),
			}
			require.NoError(t, store.CreateAuthCode(ctx, authCode))

			auth, withRefresh, err := ExchangeAuthCode(ctx, store, connCache, logger, authCode, client)
			require.NoError(t, err)
			require.Equal(t, connectorID, auth.ConnectorID)
			require.False(t, withRefresh)

			// A successful exchange preserves the normal single-use code semantics.
			_, err = store.GetAuthCode(ctx, authCode.ID)
			require.ErrorIs(t, err, storage.ErrNotFound)
		})
	}
}
