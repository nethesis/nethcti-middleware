/*
 * Copyright (C) 2026 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package methods

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"

	"github.com/nethesis/nethcti-middleware/store"
)

func setupPinMocks(t *testing.T, users legacyUsers, pins []store.ExtensionPinRow, err error) *[][]string {
	t.Helper()
	gin.SetMode(gin.TestMode)

	originalUsers := loadLegacyUsersFunc
	originalList := listExtensionPinsFunc
	t.Cleanup(func() {
		loadLegacyUsersFunc = originalUsers
		listExtensionPinsFunc = originalList
	})

	var queries [][]string
	loadLegacyUsersFunc = func() legacyUsers { return users }
	listExtensionPinsFunc = func(_ context.Context, extensions []string) ([]store.ExtensionPinRow, error) {
		queries = append(queries, extensions)
		return pins, err
	}
	return &queries
}

func runPinRequest(handler gin.HandlerFunc, user string) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodGet, "/astproxy/pin", nil)
	c.Set("JWT_PAYLOAD", jwtv5.MapClaims{"id": user})
	handler(c)
	return recorder
}

func TestGetExtensionPins_FiltersWebRTCExtensions(t *testing.T) {
	users := legacyUsers{"alice": {extensions: []legacyUserExtension{
		{id: "201", kind: "webrtc"}, {id: "91201", kind: "mobile"}, {id: "92201", kind: "nethlink"}, {id: "93201", kind: "physical"},
	}}}
	pins := []store.ExtensionPinRow{
		{Extension: 93201, Pin: sql.NullString{String: "12345", Valid: true}, Enabled: 1},
		{Extension: -5, Pin: sql.NullString{String: "\xef\xbb\xbf1\xf0\x9f\x98\x802", Valid: true}, Enabled: 2},
		{Extension: 91201, Enabled: 0},
		{Extension: 92201, Pin: sql.NullString{String: "\xed\xa0\xbd<&>", Valid: true}, Enabled: 1},
	}
	queries := setupPinMocks(t, users, pins, nil)

	recorder := runPinRequest(GetExtensionPins, "alice")

	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, `{"91201":{"extension":91201,"pin":null,"enabled":false},"92201":{"extension":92201,"pin":"\ud83d<&>","enabled":true},"93201":{"extension":93201,"pin":"12345","enabled":true},"-5":{"extension":-5,"pin":"1?2","enabled":false}}`, recorder.Body.String())
	assert.Equal(t, [][]string{{"91201", "92201", "93201"}}, *queries)
}

func TestGetExtensionPins_UserStates(t *testing.T) {
	users := legacyUsers{
		"alice": {extensions: []legacyUserExtension{{id: "201", kind: "webrtc"}}},
		"bob":   {},
		"carl":  {extensions: []legacyUserExtension{{id: "93202", kind: "physical"}, {id: "202"}}},
		"dave":  {extensions: []legacyUserExtension{{id: "93203", kind: "physical"}}},
	}
	queries := setupPinMocks(t, users, nil, nil)

	for _, user := range []string{"alice", "bob", "zed", "Alice"} {
		recorder := runPinRequest(GetExtensionPins, user)
		assert.Equal(t, http.StatusOK, recorder.Code, user)
		assert.Equal(t, `{}`, recorder.Body.String(), user)
	}

	recorder := runPinRequest(GetExtensionPins, "carl")
	assert.Equal(t, http.StatusInternalServerError, recorder.Code)
	assert.Empty(t, recorder.Body.String())
	assert.Empty(t, *queries)

	recorder = runPinRequest(GetExtensionPins, "dave")
	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, `[]`, recorder.Body.String())
}

func TestGetExtensionPins_DatabaseError(t *testing.T) {
	setupPinMocks(t, legacyUsers{"alice": {extensions: []legacyUserExtension{{id: "93201", kind: "physical"}}}}, nil, errors.New("boom"))

	recorder := runPinRequest(GetExtensionPins, "alice")

	assert.Equal(t, http.StatusInternalServerError, recorder.Code)
	assert.Empty(t, recorder.Body.String())
}

func TestGetPinStatus(t *testing.T) {
	gin.SetMode(gin.TestMode)
	original := countPinProtectedRoutesFunc
	t.Cleanup(func() { countPinProtectedRoutesFunc = original })

	cases := []struct {
		count int64
		err   error
		body  string
	}{
		{count: 2, body: `{"enabled":true}`},
		{count: 0, body: `{"enabled":false}`},
		{err: errors.New("boom"), body: `{}`},
	}
	for _, current := range cases {
		countPinProtectedRoutesFunc = func(context.Context) (int64, error) { return current.count, current.err }
		recorder := runPinRequest(GetPinStatus, "alice")
		assert.Equal(t, http.StatusOK, recorder.Code)
		assert.Equal(t, current.body, recorder.Body.String())
	}
}
