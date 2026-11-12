/*
 * Copyright (C) 2026 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package methods

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/nethesis/nethcti-middleware/configuration"
)

// v1LoginRequest records what the mock V1 server received on login.
type v1LoginRequest struct {
	headers http.Header
	body    map[string]string
	meAuth  string
}

// mockV1Login simulates the V1 login: it answers the nonce challenge, records
// the request and accepts /user/me only with the expected legacy token.
func mockV1Login(t *testing.T, expectedMeAuth string) *v1LoginRequest {
	t.Helper()
	rec := &v1LoginRequest{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/webrest/authentication/login":
			rec.headers = r.Header.Clone()
			json.NewDecoder(r.Body).Decode(&rec.body)
			w.Header().Set("Www-Authenticate", "Digest nonce123")
			w.WriteHeader(http.StatusUnauthorized)
		case "/webrest/user/me":
			rec.meAuth = r.Header.Get("Authorization")
			if rec.meAuth != expectedMeAuth {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Write([]byte(`{}`))
		case "/webrest/authentication/phone_island_token_login":
			w.Write([]byte(`{"token":"v1-persistent"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	configuration.Config.V1Protocol = "http"
	configuration.Config.V1ApiEndpoint = strings.TrimPrefix(srv.URL, "http://")
	configuration.Config.V1ApiPath = "/webrest"
	return rec
}

// legacyToken mirrors utils.GenerateLegacyToken for the "nonce123" nonce.
func legacyToken(username, key string) string {
	mac := hmac.New(sha1.New, []byte(key))
	mac.Write([]byte(username + ":" + key + ":nonce123"))
	return username + ":" + hex.EncodeToString(mac.Sum(nil))
}

func TestLoginV1Password(t *testing.T) {
	rec := mockV1Login(t, legacyToken("alice", "alice-pass"))

	token, err := LoginV1("alice", "alice-pass", LoginPassword)
	require.NoError(t, err)
	require.Equal(t, "alice:v1-persistent", token)
	require.Equal(t, "alice-pass", rec.body["password"])
	require.Empty(t, rec.headers.Get("X-SSO-User"))
	require.Empty(t, rec.headers.Get("X-Internal-User"))

	// Wrong password: the legacy token does not match
	mockV1Login(t, legacyToken("alice", "alice-pass"))
	_, err = LoginV1("alice", "wrong", LoginPassword)
	require.ErrorIs(t, err, ErrV1AuthFailed)
}

func TestLoginV1SSO(t *testing.T) {
	configuration.Config.SsoTrustedSecret = ""
	_, err := LoginV1("alice", "", LoginSSO)
	require.ErrorIs(t, err, ErrTrustedLoginDisabled)

	configuration.Config.SsoTrustedSecret = "sso-mint-secret"
	configuration.Config.SsoTokenKey = "sso-token-key"
	t.Cleanup(func() {
		configuration.Config.SsoTrustedSecret = ""
		configuration.Config.SsoTokenKey = ""
	})

	// Same requests as before the LoginV1 refactor: mint secret in the
	// headers and in the body, legacy token keyed with SsoTokenKey
	rec := mockV1Login(t, legacyToken("alice", "sso-token-key"))
	token, err := LoginV1("alice", "", LoginSSO)
	require.NoError(t, err)
	require.Equal(t, "alice:v1-persistent", token)
	require.Equal(t, "alice", rec.headers.Get("X-SSO-User"))
	require.Equal(t, "sso-mint-secret", rec.headers.Get("X-SSO-Secret"))
	require.Equal(t, "sso-mint-secret", rec.body["password"])
	require.Empty(t, rec.headers.Get("X-Internal-User"))
}

func TestLoginV1Internal(t *testing.T) {
	configuration.Config.SuperAdminToken = ""
	_, err := LoginV1("alice", "", LoginInternal)
	require.ErrorIs(t, err, ErrTrustedLoginDisabled)

	configuration.Config.SuperAdminToken = "super-admin-token"
	t.Cleanup(func() { configuration.Config.SuperAdminToken = "" })

	key := internalTokenKey("super-admin-token")
	rec := mockV1Login(t, legacyToken("alice", key))
	token, err := LoginV1("alice", "", LoginInternal)
	require.NoError(t, err)
	require.Equal(t, "alice:v1-persistent", token)
	require.Equal(t, "alice", rec.headers.Get("X-Internal-User"))
	require.Equal(t, "super-admin-token", rec.headers.Get("X-Internal-Secret"))
	require.Equal(t, key, rec.body["password"], "the secret itself must not be sent as password")
	require.Empty(t, rec.headers.Get("X-SSO-User"))
}

func TestLoginV1FailsWhenThePersistentTokenIsMissing(t *testing.T) {
	for _, answer := range []struct {
		code int
		body string
	}{{http.StatusInternalServerError, `{"token":"x"}`}, {http.StatusOK, `{"token":""}`}, {http.StatusOK, `{}`}} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/webrest/authentication/login":
				w.Header().Set("Www-Authenticate", "Digest nonce123")
				w.WriteHeader(http.StatusUnauthorized)
			case "/webrest/user/me":
				w.Write([]byte(`{}`))
			case "/webrest/authentication/phone_island_token_login":
				w.WriteHeader(answer.code)
				w.Write([]byte(answer.body))
			}
		}))
		configuration.Config.V1Protocol = "http"
		configuration.Config.V1ApiEndpoint = strings.TrimPrefix(srv.URL, "http://")
		configuration.Config.V1ApiPath = "/webrest"

		_, err := LoginV1("alice", "alice-pass", LoginPassword)
		require.ErrorIs(t, err, ErrV1AuthFailed, answer.body)
		srv.Close()
	}
}

func TestTrustedLoginHeadersAreNotProxied(t *testing.T) {
	for _, name := range []string{"X-Internal-User", "x-internal-secret", "X-SSO-User", "x-sso-secret"} {
		require.True(t, isTrustedLoginHeader(name), name)
	}
	for _, name := range []string{"Authorization", "X-Forwarded-For", "X-Internally"} {
		require.False(t, isTrustedLoginHeader(name), name)
	}
}
