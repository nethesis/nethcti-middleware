/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package methods

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"

	"github.com/nethesis/nethcti-middleware/logs"
	"github.com/nethesis/nethcti-middleware/store"
)

func init() {
	logs.Init("reload-tests")
}

// TestSuperAdminReloadSuccess verifies successful profile reload
func TestSuperAdminReloadSuccess(t *testing.T) {
	// Setup: Create temporary directory with test profiles and users
	tmpDir := t.TempDir()
	profilesPath := filepath.Join(tmpDir, "profiles.json")
	usersPath := filepath.Join(tmpDir, "users.json")

	// Write test profiles
	profilesContent := `{
		"1": {
			"id": "1",
			"name": "Base",
			"macro_permissions": {
				"phonebook": {
					"value": true,
					"permissions": [
						{"id": "12", "name": "ad_phonebook", "value": false}
					]
				}
			}
		}
	}`
	err := os.WriteFile(profilesPath, []byte(profilesContent), 0o600)
	assert.NoError(t, err, "should write profiles file")

	// Write test users
	usersContent := `{
		"testuser": {"profile_id": "1"}
	}`
	err = os.WriteFile(usersPath, []byte(usersContent), 0o600)
	assert.NoError(t, err, "should write users file")

	// Initialize store with profiles
	err = store.InitProfiles(profilesPath, usersPath)
	assert.NoError(t, err, "should initialize store")

	// Create test context
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("POST", "/admin/reload", nil)

	// Call the endpoint
	SuperAdminReload(c)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code, "should return 200")
	assert.Contains(t, w.Body.String(), "profiles reloaded successfully", "response should contain success message")
	assert.Contains(t, w.Body.String(), "api", "response should indicate API trigger")
}

// TestSuperAdminReloadWithInvalidProfilesFile verifies handling of corrupted profiles file
func TestSuperAdminReloadWithInvalidProfilesFile(t *testing.T) {
	// Setup: Create temporary directory with valid initial profiles
	tmpDir := t.TempDir()
	profilesPath := filepath.Join(tmpDir, "profiles.json")
	usersPath := filepath.Join(tmpDir, "users.json")

	// Write valid initial profiles
	profilesContent := `{
		"1": {
			"id": "1",
			"name": "Base",
			"macro_permissions": {
				"phonebook": {
					"value": true,
					"permissions": []
				}
			}
		}
	}`
	err := os.WriteFile(profilesPath, []byte(profilesContent), 0o600)
	assert.NoError(t, err)

	usersContent := `{
		"testuser": {"profile_id": "1"}
	}`
	err = os.WriteFile(usersPath, []byte(usersContent), 0o600)
	assert.NoError(t, err)

	// Initialize store
	err = store.InitProfiles(profilesPath, usersPath)
	assert.NoError(t, err)

	// Corrupt both files to ensure failure
	err = os.WriteFile(profilesPath, []byte("invalid json"), 0o600)
	assert.NoError(t, err)
	err = os.WriteFile(usersPath, []byte("invalid json"), 0o600)
	assert.NoError(t, err)

	// Create test context
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("POST", "/admin/reload", nil)

	// Call the endpoint
	SuperAdminReload(c)

	// Assertions - should return error when both files are corrupt
	assert.Equal(t, http.StatusInternalServerError, w.Code, "should return 500 when both files are corrupt")
	assert.Contains(t, w.Body.String(), "failed to reload profiles", "response should contain error message")
}

// TestSuperAdminReloadResponseStructure verifies response structure
func TestSuperAdminReloadResponseStructure(t *testing.T) {
	// Setup
	tmpDir := t.TempDir()
	profilesPath := filepath.Join(tmpDir, "profiles.json")
	usersPath := filepath.Join(tmpDir, "users.json")

	profilesContent := `{
		"1": {
			"id": "1",
			"name": "Base",
			"macro_permissions": {}
		}
	}`
	os.WriteFile(profilesPath, []byte(profilesContent), 0o600)

	usersContent := `{
		"testuser": {"profile_id": "1"}
	}`
	os.WriteFile(usersPath, []byte(usersContent), 0o600)

	store.InitProfiles(profilesPath, usersPath)

	// Create test context
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("POST", "/admin/reload", nil)

	// Call the endpoint
	SuperAdminReload(c)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "\"code\":200", "response should contain code: 200")
	assert.Contains(t, w.Body.String(), "\"message\":\"profiles reloaded successfully\"", "response should contain message")
	assert.Contains(t, w.Body.String(), "\"data\":", "response should contain data object")
	assert.Contains(t, w.Body.String(), "\"trigger\":\"api\"", "response data should contain trigger: api")
}

// TestSuperAdminReloadBroadcastFlag verifies broadcast flag is set correctly
func TestSuperAdminReloadBroadcastFlag(t *testing.T) {
	// Setup
	tmpDir := t.TempDir()
	profilesPath := filepath.Join(tmpDir, "profiles.json")
	usersPath := filepath.Join(tmpDir, "users.json")

	profilesContent := `{
		"1": {
			"id": "1",
			"name": "Base",
			"macro_permissions": {}
		}
	}`
	os.WriteFile(profilesPath, []byte(profilesContent), 0o600)

	usersContent := `{
		"testuser": {"profile_id": "1"}
	}`
	os.WriteFile(usersPath, []byte(usersContent), 0o600)

	store.InitProfiles(profilesPath, usersPath)

	// Create test context
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("POST", "/admin/reload", nil)

	// Call the endpoint
	SuperAdminReload(c)

	// Assertions - check that the broadcast flag was set
	if broadcastValue, exists := c.Get("broadcast_reload"); exists {
		assert.True(t, broadcastValue.(bool), "broadcast_reload flag should be set to true")
	} else {
		t.Fatal("broadcast_reload flag should be set in context")
	}
}
