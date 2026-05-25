/*
 * Copyright (C) 2026 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package methods

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nethesis/nethcti-middleware/store"
)

func TestComputeVisibleGroupNames(t *testing.T) {
	visibleGroups := computeVisibleGroupNames(
		"alice",
		map[string]bool{
			"presence_panel.grp_sales": true,
		},
		map[string]legacyPhonebookOperatorGroup{
			"Sales":   {Users: []string{"bob"}},
			"Support": {Users: []string{"alice"}},
			"Hidden":  {Users: []string{"charlie"}},
		},
	)

	assert.Equal(t, []string{"Sales", "Support"}, visibleGroups)
}

func TestGetLegacyCTIPhonebookContact_GroupVisibility(t *testing.T) {
	gin.SetMode(gin.TestMode)
	loadPhonebookTestProfiles(t, `{"p":{"id":"p","name":"P","macro_permissions":{"phonebook":{"value":true,"permissions":[{"id":"p2","name":"phonebook_level_2","value":true}]},"presence_panel":{"value":true,"permissions":[{"id":"grp_sales","name":"grp_sales","value":true}]}}}}`, `{"alice":{"profile_id":"p"}}`)

	originalGet := getPhonebookEntryByIDFunc
	originalFetchGroups := fetchPhonebookOperatorGroupsFunc
	originalCaps := getUserCapabilitiesFunc
	defer func() {
		getPhonebookEntryByIDFunc = originalGet
		fetchPhonebookOperatorGroupsFunc = originalFetchGroups
		getUserCapabilitiesFunc = originalCaps
	}()

	getPhonebookEntryByIDFunc = func(context.Context, int64) (*store.PhonebookEntry, error) {
		return &store.PhonebookEntry{ID: 7, OwnerID: "bob", Type: "group:Sales", Name: "Alice Shared"}, nil
	}
	fetchPhonebookOperatorGroupsFunc = func(string) (map[string]legacyPhonebookOperatorGroup, error) {
		return map[string]legacyPhonebookOperatorGroup{"Sales": {Users: []string{"bob"}}}, nil
	}
	getUserCapabilitiesFunc = func(string) (map[string]bool, error) {
		return map[string]bool{
			"phonebook":                true,
			"phonebook.phonebook_level_2": true,
			"presence_panel.grp_sales": true,
		}, nil
	}

	ctx, recorder := newLegacyPhonebookTestContext(http.MethodGet, "/phonebook/cticontact/7", nil, "alice")
	ctx.Params = gin.Params{{Key: "id", Value: "7"}}

	GetLegacyCTIPhonebookContact(ctx)

	require.Equal(t, http.StatusOK, recorder.Code)
	assert.Contains(t, recorder.Body.String(), `"source":"cti"`)
	assert.Contains(t, recorder.Body.String(), `"type":"group:Sales"`)
}

func TestGetLegacyCTIPhonebookContact_ForbiddenWhenGroupHidden(t *testing.T) {
	gin.SetMode(gin.TestMode)

	originalGet := getPhonebookEntryByIDFunc
	originalFetchGroups := fetchPhonebookOperatorGroupsFunc
	originalCaps := getUserCapabilitiesFunc
	defer func() {
		getPhonebookEntryByIDFunc = originalGet
		fetchPhonebookOperatorGroupsFunc = originalFetchGroups
		getUserCapabilitiesFunc = originalCaps
	}()

	getPhonebookEntryByIDFunc = func(context.Context, int64) (*store.PhonebookEntry, error) {
		return &store.PhonebookEntry{ID: 8, OwnerID: "bob", Type: "group:Support", Name: "Hidden Shared"}, nil
	}
	fetchPhonebookOperatorGroupsFunc = func(string) (map[string]legacyPhonebookOperatorGroup, error) {
		return map[string]legacyPhonebookOperatorGroup{"Support": {Users: []string{"bob"}}}, nil
	}
	getUserCapabilitiesFunc = func(string) (map[string]bool, error) {
		return map[string]bool{
			"phonebook":                true,
			"phonebook.phonebook_level_2": true,
		}, nil
	}

	ctx, recorder := newLegacyPhonebookTestContext(http.MethodGet, "/phonebook/cticontact/8", nil, "alice")
	ctx.Params = gin.Params{{Key: "id", Value: "8"}}

	GetLegacyCTIPhonebookContact(ctx)

	require.Equal(t, http.StatusForbidden, recorder.Code)
}

func TestCreateLegacyCTIPhonebookContact_PrivateLevelTwo(t *testing.T) {
	gin.SetMode(gin.TestMode)
	loadPhonebookTestProfiles(t, `{"p":{"id":"p","name":"P","macro_permissions":{"phonebook":{"value":true,"permissions":[{"id":"p2","name":"phonebook_level_2","value":true}]}}}}`, `{"alice":{"profile_id":"p"}}`)

	originalCreate := createPhonebookEntryFunc
	defer func() {
		createPhonebookEntryFunc = originalCreate
	}()

	var capturedEntry *store.PhonebookEntry
	createPhonebookEntryFunc = func(_ context.Context, entry *store.PhonebookEntry) error {
		capturedEntry = entry
		return nil
	}

	payload := map[string]any{
		"name":      "Alice",
		"type":      "private",
		"workphone": "+39123",
	}
	ctx, recorder := newLegacyPhonebookTestContext(http.MethodPost, "/phonebook/create", payload, "alice")

	CreateLegacyCTIPhonebookContact(ctx)

	require.Equal(t, http.StatusCreated, recorder.Code)
	require.NotNil(t, capturedEntry)
	assert.Equal(t, "alice", capturedEntry.OwnerID)
	assert.Equal(t, "private", capturedEntry.Type)
	assert.Equal(t, "+39123", capturedEntry.WorkPhone)
}

func TestCreateLegacyCTIPhonebookContact_PrivateLevelOne(t *testing.T) {
	gin.SetMode(gin.TestMode)
	loadPhonebookTestProfiles(t, `{"p":{"id":"p","name":"P","macro_permissions":{"phonebook":{"value":true,"permissions":[{"id":"p1","name":"phonebook_level_1","value":true}]}}}}`, `{"alice":{"profile_id":"p"}}`)

	originalCreate := createPhonebookEntryFunc
	defer func() {
		createPhonebookEntryFunc = originalCreate
	}()

	var capturedEntry *store.PhonebookEntry
	createPhonebookEntryFunc = func(_ context.Context, entry *store.PhonebookEntry) error {
		capturedEntry = entry
		return nil
	}

	payload := map[string]any{
		"name": "Alice",
		"type": "private",
	}
	ctx, recorder := newLegacyPhonebookTestContext(http.MethodPost, "/phonebook/create", payload, "alice")

	CreateLegacyCTIPhonebookContact(ctx)

	require.Equal(t, http.StatusCreated, recorder.Code)
	require.NotNil(t, capturedEntry)
	assert.Equal(t, "private", capturedEntry.Type)
}

func TestCreateLegacyCTIPhonebookContact_PrivateMacroOnlyForbidden(t *testing.T) {
	gin.SetMode(gin.TestMode)
	loadPhonebookTestProfiles(t, `{"p":{"id":"p","name":"P","macro_permissions":{"phonebook":{"value":true,"permissions":[]}}}}`, `{"alice":{"profile_id":"p"}}`)

	originalCreate := createPhonebookEntryFunc
	defer func() {
		createPhonebookEntryFunc = originalCreate
	}()

	createPhonebookEntryFunc = func(_ context.Context, entry *store.PhonebookEntry) error {
		t.Fatalf("create should not be called for private contacts at level 0")
		return nil
	}

	payload := map[string]any{
		"name": "Alice",
		"type": "private",
	}
	ctx, recorder := newLegacyPhonebookTestContext(http.MethodPost, "/phonebook/create", payload, "alice")

	CreateLegacyCTIPhonebookContact(ctx)

	require.Equal(t, http.StatusForbidden, recorder.Code)
}

func TestCreateLegacyCTIPhonebookContact_PublicForbiddenForLevelOne(t *testing.T) {
	gin.SetMode(gin.TestMode)
	loadPhonebookTestProfiles(t, `{"p":{"id":"p","name":"P","macro_permissions":{"phonebook":{"value":true,"permissions":[{"id":"p1","name":"phonebook_level_1","value":true}]}}}}`, `{"alice":{"profile_id":"p"}}`)

	originalCreate := createPhonebookEntryFunc
	defer func() {
		createPhonebookEntryFunc = originalCreate
	}()

	createPhonebookEntryFunc = func(_ context.Context, entry *store.PhonebookEntry) error {
		t.Fatalf("create should not be called for public contacts at level 1")
		return nil
	}

	payload := map[string]any{
		"name": "Alice",
		"type": "public",
	}
	ctx, recorder := newLegacyPhonebookTestContext(http.MethodPost, "/phonebook/create", payload, "alice")

	CreateLegacyCTIPhonebookContact(ctx)

	require.Equal(t, http.StatusForbidden, recorder.Code)
}

func TestCreateLegacyCTIPhonebookContact_PublicAllowedForLevelTwo(t *testing.T) {
	gin.SetMode(gin.TestMode)
	loadPhonebookTestProfiles(t, `{"p":{"id":"p","name":"P","macro_permissions":{"phonebook":{"value":true,"permissions":[{"id":"p2","name":"phonebook_level_2","value":true}]}}}}`, `{"alice":{"profile_id":"p"}}`)

	originalCreate := createPhonebookEntryFunc
	defer func() {
		createPhonebookEntryFunc = originalCreate
	}()

	var capturedEntry *store.PhonebookEntry
	createPhonebookEntryFunc = func(_ context.Context, entry *store.PhonebookEntry) error {
		capturedEntry = entry
		return nil
	}

	payload := map[string]any{
		"name": "Alice",
		"type": "public",
	}
	ctx, recorder := newLegacyPhonebookTestContext(http.MethodPost, "/phonebook/create", payload, "alice")

	CreateLegacyCTIPhonebookContact(ctx)

	require.Equal(t, http.StatusCreated, recorder.Code)
	require.NotNil(t, capturedEntry)
	assert.Equal(t, "public", capturedEntry.Type)
}

func TestUpdateLegacyCTIPhonebookContact_RejectsVisibilityEscalation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	loadPhonebookTestProfiles(t, `{"p":{"id":"p","name":"P","macro_permissions":{"phonebook":{"value":true,"permissions":[{"id":"p1","name":"phonebook_level_1","value":true}]}}}}`, `{"alice":{"profile_id":"p"}}`)

	originalGet := getPhonebookEntryByIDFunc
	originalUpdate := updatePhonebookEntryFieldsFunc
	defer func() {
		getPhonebookEntryByIDFunc = originalGet
		updatePhonebookEntryFieldsFunc = originalUpdate
	}()

	getPhonebookEntryByIDFunc = func(context.Context, int64) (*store.PhonebookEntry, error) {
		return &store.PhonebookEntry{ID: 9, OwnerID: "alice", Type: "private", Name: "Alice"}, nil
	}
	updatePhonebookEntryFieldsFunc = func(context.Context, int64, map[string]any) error {
		t.Fatalf("update should not be called when visibility escalation is forbidden")
		return nil
	}

	payload := map[string]any{
		"id":   "9",
		"type": "public",
	}
	ctx, recorder := newLegacyPhonebookTestContext(http.MethodPost, "/phonebook/modify_cticontact", payload, "alice")

	UpdateLegacyCTIPhonebookContact(ctx)

	require.Equal(t, http.StatusForbidden, recorder.Code)
}

func TestSearchLegacyPhonebook_UsesMiddlewareQuery(t *testing.T) {
	gin.SetMode(gin.TestMode)

	originalSearch := searchLegacyPhonebookFunc
	originalFetchGroups := fetchPhonebookOperatorGroupsFunc
	originalCaps := getUserCapabilitiesFunc
	defer func() {
		searchLegacyPhonebookFunc = originalSearch
		fetchPhonebookOperatorGroupsFunc = originalFetchGroups
		getUserCapabilitiesFunc = originalCaps
	}()

	var capturedQuery store.LegacyPhonebookQuery
	searchLegacyPhonebookFunc = func(_ context.Context, query store.LegacyPhonebookQuery) (*store.LegacyPhonebookResult, error) {
		capturedQuery = query
		return &store.LegacyPhonebookResult{Count: 1, Rows: []store.LegacyPhonebookContact{{Name: "Alice", Source: "cti"}}}, nil
	}
	fetchPhonebookOperatorGroupsFunc = func(string) (map[string]legacyPhonebookOperatorGroup, error) {
		return map[string]legacyPhonebookOperatorGroup{"Sales": {Users: []string{"alice"}}}, nil
	}
	getUserCapabilitiesFunc = func(string) (map[string]bool, error) {
		return map[string]bool{"phonebook": true}, nil
	}

	ctx, recorder := newLegacyPhonebookTestContext(http.MethodGet, "/phonebook/search?view=company&offset=0&limit=10", nil, "alice")
	ctx.Params = gin.Params{{Key: "term", Value: ""}}

	SearchLegacyPhonebook(ctx)

	require.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, "alice", capturedQuery.Username)
	assert.Equal(t, "company", capturedQuery.View)
	assert.Equal(t, 0, capturedQuery.Offset)
	assert.Equal(t, 10, capturedQuery.Limit)
	assert.True(t, capturedQuery.ApplyPagination)
	assert.True(t, capturedQuery.IncludePrivateContacts)
	assert.Equal(t, []string{"Sales"}, capturedQuery.UserGroups)
	assert.Contains(t, recorder.Body.String(), `"count":1`)
}

func TestListLegacyPhonebook_UsesMiddlewareQuery(t *testing.T) {
	gin.SetMode(gin.TestMode)

	originalList := listLegacyPhonebookFunc
	originalFetchGroups := fetchPhonebookOperatorGroupsFunc
	originalCaps := getUserCapabilitiesFunc
	defer func() {
		listLegacyPhonebookFunc = originalList
		fetchPhonebookOperatorGroupsFunc = originalFetchGroups
		getUserCapabilitiesFunc = originalCaps
	}()

	var capturedQuery store.LegacyPhonebookQuery
	listLegacyPhonebookFunc = func(_ context.Context, query store.LegacyPhonebookQuery) (*store.LegacyPhonebookResult, error) {
		capturedQuery = query
		return &store.LegacyPhonebookResult{Count: 0, Rows: []store.LegacyPhonebookContact{}}, nil
	}
	fetchPhonebookOperatorGroupsFunc = func(string) (map[string]legacyPhonebookOperatorGroup, error) {
		return map[string]legacyPhonebookOperatorGroup{}, nil
	}
	getUserCapabilitiesFunc = func(string) (map[string]bool, error) {
		return map[string]bool{"phonebook": true}, nil
	}

	ctx, recorder := newLegacyPhonebookTestContext(http.MethodGet, "/phonebook/getall?offset=5&limit=20", nil, "alice")

	ListLegacyPhonebook(ctx)

	require.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, "alice", capturedQuery.Username)
	assert.Equal(t, 5, capturedQuery.Offset)
	assert.Equal(t, 20, capturedQuery.Limit)
	assert.True(t, capturedQuery.ApplyPagination)
	assert.True(t, capturedQuery.IncludePrivateContacts)
	assert.Empty(t, capturedQuery.Term)
	assert.Contains(t, recorder.Body.String(), `"count":0`)
}

func newLegacyPhonebookTestContext(method, target string, payload map[string]any, username string) (*gin.Context, *httptest.ResponseRecorder) {
	var body *bytes.Reader
	if payload == nil {
		body = bytes.NewReader(nil)
	} else {
		payloadBytes, _ := json.Marshal(payload)
		body = bytes.NewReader(payloadBytes)
	}

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(method, target, body)
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Set("JWT_PAYLOAD", jwtv5.MapClaims{"id": username})
	return ctx, recorder
}

func loadPhonebookTestProfiles(t *testing.T, profilesJSON, usersJSON string) {
	t.Helper()
	tempDir := t.TempDir()
	profilesPath := filepath.Join(tempDir, "profiles.json")
	usersPath := filepath.Join(tempDir, "users.json")
	require.NoError(t, os.WriteFile(profilesPath, []byte(profilesJSON), 0o600))
	require.NoError(t, os.WriteFile(usersPath, []byte(usersJSON), 0o600))
	require.NoError(t, store.InitProfiles(profilesPath, usersPath))
}