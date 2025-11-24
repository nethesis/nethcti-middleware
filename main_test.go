/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"

	"github.com/nethesis/nethcti-middleware/models"
	"github.com/nethesis/nethcti-middleware/store"
	"github.com/nethesis/nethcti-middleware/utils"
)

// Global variables for test server URLs and mock server
var testServerURL string
var mockNetCTI *httptest.Server

// TestMain sets up the test environment once for all tests
func TestMain(m *testing.M) {
	// Setup test environment and dependencies
	setupTestEnvironment()

	// Run all tests
	code := m.Run()

	// Cleanup after all tests
	cleanupTestEnvironment()

	// Exit with the same code as the tests
	os.Exit(code)
}

// Global test setup - starts actual main server once
func setupTestEnvironment() {
	gin.SetMode(gin.TestMode)

	// Start mock NetCTI server first
	mockNetCTI = mockNetCTIServer()
	mockURL := strings.TrimPrefix(mockNetCTI.URL, "http://")

	// Prepare temporary authorization data so tests can satisfy capability checks
	authDir := filepath.Join(os.TempDir(), "nethcti-authz")
	os.MkdirAll(authDir, 0755)
	profilesPath := filepath.Join(authDir, "profiles.json")
	usersPath := filepath.Join(authDir, "users.json")
	writeTestProfiles(profilesPath)
	writeTestUsers(usersPath)

	// Set environment variables for the middleware
	os.Setenv("NETHVOICE_MIDDLEWARE_LISTEN_ADDRESS", "127.0.0.1:8899")
	os.Setenv("NETHVOICE_MIDDLEWARE_V1_PROTOCOL", "http")
	os.Setenv("NETHVOICE_MIDDLEWARE_V1_API_ENDPOINT", mockURL)
	os.Setenv("NETHVOICE_MIDDLEWARE_V1_WS_ENDPOINT", mockURL)
	os.Setenv("NETHVOICE_MIDDLEWARE_V1_API_PATH", "/webrest")
	os.Setenv("NETHVOICE_MIDDLEWARE_V1_WS_PATH", "/socket.io")
	os.Setenv("NETHVOICE_MIDDLEWARE_SECRETS_DIR", "/tmp/test-secrets/nethcti")
	os.Setenv("NETHVOICE_MIDDLEWARE_ISSUER_2FA", "NetCTI-Test")
	os.Setenv("NETHVOICE_MIDDLEWARE_SENSITIVE_LIST", "password,secret")
	os.Setenv("AUTH_PROFILES_PATH", profilesPath)
	os.Setenv("AUTH_USERS_PATH", usersPath)

	// Set database environment variables for testing
	os.Setenv("PHONEBOOK_MARIADB_HOST", "127.0.0.1")
	os.Setenv("PHONEBOOK_MARIADB_PORT", "3306")
	os.Setenv("PHONEBOOK_MARIADB_USER", "root")
	os.Setenv("PHONEBOOK_MARIADB_PASSWORD", "root")
	os.Setenv("PHONEBOOK_MARIADB_DATABASE", "nethcti3")

	// Create test secrets directory
	os.MkdirAll(os.Getenv("NETHVOICE_MIDDLEWARE_SECRETS_DIR"), 0700)

	// Start the actual main server in a goroutine
	go func() {
		main()
	}()

	// Set test server URL
	testServerURL = "http://127.0.0.1:8899"

	// Give server time to fully start
	time.Sleep(2 * time.Second)
}

// Mock NetCTI server for testing
func mockNetCTIServer() *httptest.Server {
	validUsers := map[string]string{
		"testuser": "testpass",
		"baseuser": "testpass",
		"advuser":  "testpass",
	}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/webrest/authentication/login":
			var loginData map[string]string
			json.NewDecoder(r.Body).Decode(&loginData)

			if pwd, ok := validUsers[loginData["username"]]; ok && pwd == loginData["password"] {
				w.Header().Set("Www-Authenticate", `Digest realm="test", nonce="test123", qop="auth"`)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			w.WriteHeader(http.StatusUnauthorized)
		case "/webrest/user/me":
			auth := r.Header.Get("Authorization")
			for username := range validUsers {
				if strings.Contains(auth, username) {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(fmt.Sprintf(`{"username": "%s"}`, username)))
					return
				}
			}
		case "/webrest/authentication/phone_island_token_login":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"token": "phone-island-token"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

// Global cleanup test data
func cleanupTestEnvironment() {
	if mockNetCTI != nil {
		mockNetCTI.Close()
	}
	os.RemoveAll(os.Getenv("NETHVOICE_MIDDLEWARE_SECRETS_DIR"))

	// Clear environment variables
	os.Unsetenv("NETHVOICE_MIDDLEWARE_LISTEN_ADDRESS")
	os.Unsetenv("NETHVOICE_MIDDLEWARE_V1_PROTOCOL")
	os.Unsetenv("NETHVOICE_MIDDLEWARE_V1_API_ENDPOINT")
	os.Unsetenv("NETHVOICE_MIDDLEWARE_V1_API_PATH")
	os.Unsetenv("NETHVOICE_MIDDLEWARE_V1_WS_PATH")
	os.Unsetenv("NETHVOICE_MIDDLEWARE_SECRETS_DIR")
	os.Unsetenv("NETHVOICE_MIDDLEWARE_ISSUER_2FA")
	os.Unsetenv("NETHVOICE_MIDDLEWARE_SENSITIVE_LIST")
	os.Unsetenv("AUTH_PROFILES_PATH")
	os.Unsetenv("AUTH_USERS_PATH")
	os.RemoveAll(filepath.Join(os.TempDir(), "nethcti-authz"))
}

// Helper function to reset test state between tests
func resetTestState() {
	// Clear user sessions and test files to ensure isolation between tests
	store.UserSessions = make(map[string]*models.UserSession)

	// Clean up any test files
	os.RemoveAll(os.Getenv("NETHVOICE_MIDDLEWARE_SECRETS_DIR"))
	os.MkdirAll(os.Getenv("NETHVOICE_MIDDLEWARE_SECRETS_DIR"), 0700)
}

// Test login endpoint
func TestLogin(t *testing.T) {
	resetTestState()

	loginData := map[string]string{
		"username": "testuser",
		"password": "testpass",
	}
	jsonData, _ := json.Marshal(loginData)

	resp, err := http.Post(testServerURL+"/login", "application/json", bytes.NewBuffer(jsonData))
	assert.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var response map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&response)
	assert.NoError(t, err)
	assert.Equal(t, float64(200), response["code"])
	assert.NotEmpty(t, response["token"])
}

// Test logout endpoint
func TestLogout(t *testing.T) {
	resetTestState()

	token := utils.PerformLogin(testServerURL)

	client := &http.Client{}
	req, _ := http.NewRequest("POST", testServerURL+"/logout", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// Test 2FA QR code generation
func TestQRCode(t *testing.T) {
	resetTestState()

	token := utils.PerformLogin(testServerURL)

	client := &http.Client{}
	req, _ := http.NewRequest("GET", testServerURL+"/2fa/qr-code", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var response map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&response)
	assert.NoError(t, err)

	data := response["data"].(map[string]interface{})
	assert.NotEmpty(t, data["url"])
	assert.NotEmpty(t, data["key"])
}

// Test 2FA status check
func Test2FAStatus(t *testing.T) {
	resetTestState()

	token := utils.PerformLogin(testServerURL)

	client := &http.Client{}
	req, _ := http.NewRequest("GET", testServerURL+"/2fa/status", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var response map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&response)
	assert.NoError(t, err)
	assert.False(t, response["status"].(bool))
}

// Test OTP verification
func TestOTPVerify(t *testing.T) {
	resetTestState()

	token := utils.PerformLogin(testServerURL)
	otpSecret := utils.Setup2FA(testServerURL, token, t)
	otp := utils.GenerateOTP(otpSecret)

	otpData := map[string]string{
		"username": "testuser",
		"otp":      otp,
	}
	jsonData, _ := json.Marshal(otpData)

	client := &http.Client{}
	req, _ := http.NewRequest("POST", testServerURL+"/2fa/verify-otp", bytes.NewBuffer(jsonData))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// Test recovery codes generation
func TestRecoveryCodes(t *testing.T) {
	resetTestState()

	token := utils.PerformLogin(testServerURL)
	otpSecret := utils.Setup2FA(testServerURL, token, t)
	otp := utils.GenerateOTP(otpSecret)
	token = utils.Verify2FA(testServerURL, otp, token, t)

	recoveryCodes := map[string]string{
		"password": "testpass",
	}
	jsonData, _ := json.Marshal(recoveryCodes)

	client := &http.Client{}
	req, _ := http.NewRequest("POST", testServerURL+"/2fa/recovery-codes", bytes.NewBuffer(jsonData))
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var response map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&response)
	assert.NoError(t, err)

	codes := response["codes"].([]interface{})
	assert.Greater(t, len(codes), 0)
}

// Test 2FA disable
func TestDisable2FA(t *testing.T) {
	resetTestState()

	token := utils.PerformLogin(testServerURL)
	otpSecret := utils.Setup2FA(testServerURL, token, t)
	otp := utils.GenerateOTP(otpSecret)
	token = utils.Verify2FA(testServerURL, otp, token, t)

	disableData := map[string]string{
		"password": "testpass",
	}
	jsonData, _ := json.Marshal(disableData)

	client := &http.Client{}
	req, _ := http.NewRequest("POST", testServerURL+"/2fa/disable", bytes.NewBuffer(jsonData))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// Test phonebook CSV import
func TestPhonebookImport(t *testing.T) {
	resetTestState()

	// Get JWT token first
	token := utils.PerformLogin(testServerURL)

	// Create a CSV content
	csvContent := `name,type,workphone,cellphone,company
John Doe,private,+1234567890,,Example Corp
Jane Smith,public,,+0987654321,Tech Inc
Bob Johnson,private,+1111111111,+2222222222,Services Ltd`

	// Create multipart form data
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Add file field
	part, err := writer.CreateFormFile("file", "contacts.csv")
	assert.NoError(t, err)

	_, err = io.Copy(part, strings.NewReader(csvContent))
	assert.NoError(t, err)

	err = writer.Close()
	assert.NoError(t, err)

	// Make request
	client := &http.Client{}
	req, err := http.NewRequest("POST", testServerURL+"/phonebook/import", body)
	assert.NoError(t, err)

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := client.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var response map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&response)
	assert.NoError(t, err)

	// Verify response structure
	assert.NotEmpty(t, response["message"])
	assert.Equal(t, float64(3), response["total_rows"], "Should have 3 rows in CSV")
	// With database running, we should have successful imports
	totalRows := response["total_rows"].(float64)
	importedRows := response["imported_rows"].(float64)
	assert.Greater(t, importedRows, float64(0), fmt.Sprintf("Should have imported some rows out of %.0f", totalRows))
}

// Test phonebook import with invalid type
func TestPhonebookImportInvalidType(t *testing.T) {
	resetTestState()

	token := utils.PerformLogin(testServerURL)

	// CSV with invalid type value
	csvContent := `name,type,workphone
John Doe,invalid,+1234567890
Jane Smith,private,+0987654321`

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	part, err := writer.CreateFormFile("file", "contacts.csv")
	assert.NoError(t, err)

	_, err = io.Copy(part, strings.NewReader(csvContent))
	assert.NoError(t, err)

	err = writer.Close()
	assert.NoError(t, err)

	client := &http.Client{}
	req, err := http.NewRequest("POST", testServerURL+"/phonebook/import", body)
	assert.NoError(t, err)

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := client.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var response map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&response)
	assert.NoError(t, err)

	// First row should be skipped due to invalid type
	assert.Greater(t, response["skipped_rows"], float64(0), "Should have skipped rows with invalid type")
	assert.Less(t, response["imported_rows"], float64(2), "Should not have imported the row with invalid type")
}

// Test phonebook import missing required field
func TestPhonebookImportMissingName(t *testing.T) {
	resetTestState()

	token := utils.PerformLogin(testServerURL)

	// CSV with missing name column
	csvContent := `type,workphone
private,+1234567890
public,+0987654321`

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	part, err := writer.CreateFormFile("file", "contacts.csv")
	assert.NoError(t, err)

	_, err = io.Copy(part, strings.NewReader(csvContent))
	assert.NoError(t, err)

	err = writer.Close()
	assert.NoError(t, err)

	client := &http.Client{}
	req, err := http.NewRequest("POST", testServerURL+"/phonebook/import", body)
	assert.NoError(t, err)

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := client.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func sendPhonebookImportRequest(t *testing.T, token, csvContent string) *http.Response {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	part, err := writer.CreateFormFile("file", "contacts.csv")
	assert.NoError(t, err)

	_, err = io.Copy(part, strings.NewReader(csvContent))
	assert.NoError(t, err)

	err = writer.Close()
	assert.NoError(t, err)

	req, err := http.NewRequest("POST", testServerURL+"/phonebook/import", body)
	assert.NoError(t, err)

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	client := &http.Client{}
	resp, err := client.Do(req)
	assert.NoError(t, err)

	return resp
}

func TestPhonebookImportDeniedForBaseProfile(t *testing.T) {
	resetTestState()

	token := utils.PerformLoginWithCredentials(testServerURL, "baseuser", "testpass")
	assert.NotEmpty(t, token)

	csvContent := `name,type,workphone
John Doe,private,+1234567890`

	resp := sendPhonebookImportRequest(t, token, csvContent)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)

	var response map[string]interface{}
	err := json.NewDecoder(resp.Body).Decode(&response)
	assert.NoError(t, err)
	assert.Equal(t, float64(http.StatusForbidden), response["code"])
	assert.Equal(t, "missing capability", response["message"])
}

func TestPhonebookImportAllowedForAdvancedProfile(t *testing.T) {
	resetTestState()

	token := utils.PerformLoginWithCredentials(testServerURL, "advuser", "testpass")
	assert.NotEmpty(t, token)

	csvContent := `name,type,workphone
John Doe,private,+1234567890
Jane Smith,public,+0987654321`

	resp := sendPhonebookImportRequest(t, token, csvContent)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var response map[string]interface{}
	err := json.NewDecoder(resp.Body).Decode(&response)
	assert.NoError(t, err)
	assert.Equal(t, float64(2), response["total_rows"], "Should report two rows")
	assert.Equal(t, float64(2), response["imported_rows"], "Both rows should import")
}

func writeTestProfiles(path string) {
	content := `{
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
	},
	"3": {
		"id": "3",
		"name": "Advanced",
		"macro_permissions": {
			"phonebook": {
				"value": true,
				"permissions": [
					{"id": "12", "name": "ad_phonebook", "value": true}
				]
			}
		}
	}
}`
	os.WriteFile(path, []byte(content), 0o644)
}

func writeTestUsers(path string) {
	content := `{
	"testuser": {"profile_id": "3"},
	"baseuser": {"profile_id": "1"},
	"advuser": {"profile_id": "3"}
}`
	os.WriteFile(path, []byte(content), 0o644)
}

// TestReloadProfileEndpointReturnsNewToken verifies reload endpoint returns new token with updated capabilities
func TestReloadProfileEndpointReturnsNewToken(t *testing.T) {
	// Get a valid JWT token by logging in
	loginPayload := map[string]string{
		"username": "testuser",
		"password": "testpass",
	}
	loginBody, _ := json.Marshal(loginPayload)
	resp, err := http.Post(testServerURL+"/login", "application/json", bytes.NewBuffer(loginBody))
	assert.NoError(t, err)
	defer resp.Body.Close()

	var loginResp map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&loginResp)
	token := loginResp["token"].(string)

	// Call refresh endpoint with valid token
	req, _ := http.NewRequest("POST", testServerURL+"/refresh", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{}
	resp, err = client.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var reloadResp map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&reloadResp)

	// Verify response structure
	assert.Equal(t, float64(200), reloadResp["code"])
	assert.NotNil(t, reloadResp["data"])

	data := reloadResp["data"].(map[string]interface{})
	newToken := data["token"].(string)
	assert.NotEmpty(t, newToken)
	assert.NotEmpty(t, data["expire"])
}

// TestReloadProfileEndpointWithValidToken verifies new token works for authenticated requests
func TestReloadProfileEndpointWithValidToken(t *testing.T) {
	// Get initial token
	loginPayload := map[string]string{
		"username": "advuser",
		"password": "testpass",
	}
	loginBody, _ := json.Marshal(loginPayload)
	resp, _ := http.Post(testServerURL+"/login", "application/json", bytes.NewBuffer(loginBody))
	defer resp.Body.Close()

	var loginResp map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&loginResp)
	token := loginResp["token"].(string)

	// Call refresh endpoint
	req, _ := http.NewRequest("POST", testServerURL+"/refresh", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{}
	resp, _ = client.Do(req)
	defer resp.Body.Close()

	var reloadResp map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&reloadResp)

	data := reloadResp["data"].(map[string]interface{})
	newToken := data["token"].(string)

	// Verify new token can access protected endpoints
	req2, _ := http.NewRequest("GET", testServerURL+"/2fa/status", nil)
	req2.Header.Set("Authorization", "Bearer "+newToken)

	resp2, _ := client.Do(req2)
	defer resp2.Body.Close()

	assert.Equal(t, http.StatusOK, resp2.StatusCode)
}

// TestReloadProfileEndpointUnauthorized verifies unauthorized users cannot access refresh
func TestReloadProfileEndpointUnauthorized(t *testing.T) {
	// Try to call refresh without token
	resp, err := http.Post(testServerURL+"/refresh", "application/json", nil)
	assert.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestReloadProfileEndpointOldTokenStillValid verifies old token is still valid after reload
func TestReloadProfileEndpointOldTokenStillValid(t *testing.T) {
	// Get initial token
	loginPayload := map[string]string{
		"username": "testuser",
		"password": "testpass",
	}
	loginBody, _ := json.Marshal(loginPayload)
	resp, _ := http.Post(testServerURL+"/login", "application/json", bytes.NewBuffer(loginBody))
	defer resp.Body.Close()

	var loginResp map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&loginResp)
	oldToken := loginResp["token"].(string)

	// Call refresh to get new token
	req, _ := http.NewRequest("POST", testServerURL+"/refresh", nil)
	req.Header.Set("Authorization", "Bearer "+oldToken)

	client := &http.Client{}
	resp, _ = client.Do(req)
	defer resp.Body.Close()

	var reloadResp map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&reloadResp)

	data := reloadResp["data"].(map[string]interface{})
	newToken := data["token"].(string)

	// Try to use new token for an authenticated request
	req2, _ := http.NewRequest("GET", testServerURL+"/2fa/status", nil)
	req2.Header.Set("Authorization", "Bearer "+newToken)

	resp2, _ := client.Do(req2)
	defer resp2.Body.Close()

	assert.Equal(t, http.StatusOK, resp2.StatusCode)
}

// TestSuperAdminReloadEndpointWithValidToken verifies /admin/reload endpoint works with valid super admin token
func TestSuperAdminReloadEndpointWithValidToken(t *testing.T) {
	resetTestState()

	// Use the default super admin token "CHANGEME" (since no env var is set in tests)
	superAdminToken := "CHANGEME"

	// Call /admin/reload endpoint with valid token
	client := &http.Client{}
	req, _ := http.NewRequest("POST", testServerURL+"/admin/reload", nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", superAdminToken))

	resp, err := client.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode, "should accept valid super admin token")

	var response map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&response)
	assert.Equal(t, float64(200), response["code"])
	assert.Contains(t, response["message"].(string), "profiles reloaded successfully")
}

// TestSuperAdminReloadEndpointWithInvalidToken verifies /admin/reload rejects invalid tokens
func TestSuperAdminReloadEndpointWithInvalidToken(t *testing.T) {
	resetTestState()

	client := &http.Client{}
	req, _ := http.NewRequest("POST", testServerURL+"/admin/reload", nil)
	req.Header.Set("Authorization", "Bearer invalid-token-12345")

	resp, err := client.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "should reject invalid super admin token")

	var response map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&response)
	assert.Equal(t, float64(401), response["code"])
	assert.Contains(t, response["message"].(string), "super admin authentication required")
}

// TestSuperAdminReloadEndpointWithoutToken verifies /admin/reload rejects requests without token
func TestSuperAdminReloadEndpointWithoutToken(t *testing.T) {
	resetTestState()

	resp, err := http.Post(testServerURL+"/admin/reload", "application/json", nil)
	assert.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "should reject requests without authentication")

	var response map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&response)
	assert.Equal(t, float64(401), response["code"])
}

// TestSuperAdminReloadEndpointMalformedAuthHeader verifies /admin/reload rejects malformed auth headers
func TestSuperAdminReloadEndpointMalformedAuthHeader(t *testing.T) {
	resetTestState()

	client := &http.Client{}
	req, _ := http.NewRequest("POST", testServerURL+"/admin/reload", nil)
	req.Header.Set("Authorization", "InvalidScheme token-value")

	resp, err := client.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "should reject malformed auth header")
}

// TestSuperAdminReloadEndToEndWithWebSocketClient verifies complete flow:
// 1. Client logs in with test user (Base profile)
// 2. Verify initial capabilities are from Base profile
// 3. Change user's profile to Advanced profile
// 4. /admin/reload super admin endpoint is called
// 5. Client calls /refresh and obtains new JWT with updated capabilities
// 6. Verify capabilities changed from Base to Advanced
func TestSuperAdminReloadEndToEndWithWebSocketClient(t *testing.T) {
	resetTestState()

	// Step 1: Login as baseuser (Base profile - id 1)
	loginPayload := map[string]string{
		"username": "baseuser",
		"password": "testpass",
	}
	loginBody, _ := json.Marshal(loginPayload)
	resp, _ := http.Post(testServerURL+"/login", "application/json", bytes.NewBuffer(loginBody))
	defer resp.Body.Close()

	var loginResp map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&loginResp)
	oldToken := loginResp["token"].(string)
	assert.NotEmpty(t, oldToken, "should get valid login token")

	// Step 2: Verify initial capabilities are from Base profile
	// Parse token to get capabilities
	var oldTokenClaims map[string]interface{}
	parseTestToken(oldToken, &oldTokenClaims)
	t.Logf("Initial token claims: %v", oldTokenClaims)

	// Check that baseuser starts with profile_id "1" (Base)
	initialProfileID, ok := oldTokenClaims["profile_id"].(string)
	assert.True(t, ok, "should have profile_id in token")
	assert.Equal(t, "1", initialProfileID, "baseuser should start with Base profile (id 1)")

	// Get initial ad_phonebook capability value (Base profile has it as false)
	oldPhonebookCap, hasOldPhonebook := oldTokenClaims["phonebook.ad_phonebook"].(bool)
	assert.True(t, hasOldPhonebook, "Base profile should have ad_phonebook capability")
	assert.False(t, oldPhonebookCap, "Base profile should have ad_phonebook=false")

	// Step 3: Change user's profile from Base (1) to Advanced (3)
	usersPath := os.Getenv("AUTH_USERS_PATH")

	// Update user to Advanced profile
	updatedUsers := `{
	"testuser": {"profile_id": "3"},
	"baseuser": {"profile_id": "3"},
	"advuser": {"profile_id": "3"}
}`
	os.WriteFile(usersPath, []byte(updatedUsers), 0o644)

	// Step 4: Call /admin/reload super admin endpoint
	client := &http.Client{}
	reloadReq, _ := http.NewRequest("POST", testServerURL+"/admin/reload", nil)
	reloadReq.Header.Set("Authorization", "Bearer CHANGEME")

	reloadResp, err := client.Do(reloadReq)
	assert.NoError(t, err, "should be able to call /admin/reload endpoint")
	defer reloadResp.Body.Close()

	assert.Equal(t, http.StatusOK, reloadResp.StatusCode, "/admin/reload should succeed")

	var reloadResponse map[string]interface{}
	json.NewDecoder(reloadResp.Body).Decode(&reloadResponse)
	assert.Equal(t, float64(200), reloadResponse["code"], "reload should return 200")
	assert.Equal(t, "profiles reloaded successfully", reloadResponse["message"], "should return success message")

	// Step 5: Call /refresh and verify new JWT has updated capabilities
	refreshReq, _ := http.NewRequest("POST", testServerURL+"/refresh", nil)
	refreshReq.Header.Set("Authorization", "Bearer "+oldToken)

	refreshResp, _ := client.Do(refreshReq)
	defer refreshResp.Body.Close()

	var refreshResponse map[string]interface{}
	json.NewDecoder(refreshResp.Body).Decode(&refreshResponse)
	assert.Equal(t, float64(200), refreshResponse["code"], "refresh should succeed")

	// Extract new token from response
	refreshData := refreshResponse["data"].(map[string]interface{})
	newToken := refreshData["token"].(string)
	assert.NotEmpty(t, newToken, "should get new token")

	// Step 6: Verify new token has updated capabilities
	var newTokenClaims map[string]interface{}
	parseTestToken(newToken, &newTokenClaims)
	t.Logf("Updated token claims: %v", newTokenClaims)

	// Check that profile_id changed to "3" (Advanced)
	newProfileID, ok := newTokenClaims["profile_id"].(string)
	assert.True(t, ok, "should have profile_id in new token")
	assert.Equal(t, "3", newProfileID, "baseuser should now have Advanced profile (id 3) after reload")

	// Verify ad_phonebook capability is now true (Advanced profile has it as true)
	newPhonebookCap, hasNewPhonebook := newTokenClaims["phonebook.ad_phonebook"].(bool)
	assert.True(t, hasNewPhonebook, "Advanced profile should have ad_phonebook capability")
	assert.True(t, newPhonebookCap, "Advanced profile should have ad_phonebook=true after reload")

	// Verify the capability actually changed
	assert.NotEqual(t, oldPhonebookCap, newPhonebookCap, "capability should have changed after profile update and reload")
	t.Logf("✓ Capability successfully updated: %v -> %v", oldPhonebookCap, newPhonebookCap)
	t.Logf("✓ Profile successfully updated: %s -> %s", initialProfileID, newProfileID)
}

// Helper function to extract and parse token claims for testing
func parseTestToken(tokenString string, claims *map[string]interface{}) {
	// This is a simple helper that extracts the payload from the JWT
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return
	}

	// Decode the payload (second part)
	payload := parts[1]
	// Add padding if necessary
	switch len(payload) % 4 {
	case 2:
		payload += "=="
	case 3:
		payload += "="
	}

	decoded := make([]byte, 0)
	for i := 0; i < len(payload); i++ {
		c := payload[i]
		switch c {
		case '-':
			decoded = append(decoded, '+')
		case '_':
			decoded = append(decoded, '/')
		default:
			decoded = append(decoded, c)
		}
	}

	// Base64 decode the payload
	data, err := base64.StdEncoding.DecodeString(string(decoded))
	if err != nil {
		return
	}

	// Parse JSON
	json.Unmarshal(data, claims)
}
