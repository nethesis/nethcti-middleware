/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
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

	// Set environment variables for the middleware
	os.Setenv("NETHVOICE_MIDDLEWARE_LISTEN_ADDRESS", "127.0.0.1:8899")
	os.Setenv("NETHVOICE_MIDDLEWARE_V1_PROTOCOL", "http")
	os.Setenv("NETHVOICE_MIDDLEWARE_V1_API_ENDPOINT", mockURL)
	os.Setenv("NETHVOICE_MIDDLEWARE_V1_API_PATH", "/webrest")
	os.Setenv("NETHVOICE_MIDDLEWARE_V1_WS_PATH", "/ws")
	os.Setenv("NETHVOICE_MIDDLEWARE_SECRET_JWT", "test-secret-key-for-jwt-tokens")
	os.Setenv("NETHVOICE_MIDDLEWARE_SECRETS_DIR", "/tmp/test-secrets")
	os.Setenv("NETHVOICE_MIDDLEWARE_ISSUER_2FA", "NetCTI-Test")
	os.Setenv("NETHVOICE_MIDDLEWARE_SENSITIVE_LIST", "password,secret")

	// Create test secrets directory
	os.MkdirAll("/tmp/test-secrets", 0700)

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
	// This mock server simulates the NetCTI backend for authentication and user info
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/webrest/authentication/login" {
			var loginData map[string]string
			json.NewDecoder(r.Body).Decode(&loginData)

			// Simulate Digest authentication challenge for correct credentials
			if loginData["username"] == "testuser" && loginData["password"] == "testpass" {
				w.Header().Set("Www-Authenticate", `Digest realm="test", nonce="test123", qop="auth"`)
				w.WriteHeader(http.StatusUnauthorized)
			} else {
				w.WriteHeader(http.StatusUnauthorized)
			}
		} else if r.URL.Path == "/webrest/user/me" {
			auth := r.Header.Get("Authorization")
			if strings.Contains(auth, "testuser") {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"username": "testuser"}`))
			} else {
				w.WriteHeader(http.StatusUnauthorized)
			}
		}
	}))
}

// Global cleanup test data
func cleanupTestEnvironment() {
	if mockNetCTI != nil {
		mockNetCTI.Close()
	}
	os.RemoveAll("/tmp/test-secrets")

	// Clear environment variables
	os.Unsetenv("NETHVOICE_MIDDLEWARE_LISTEN_ADDRESS")
	os.Unsetenv("NETHVOICE_MIDDLEWARE_V1_PROTOCOL")
	os.Unsetenv("NETHVOICE_MIDDLEWARE_V1_API_ENDPOINT")
	os.Unsetenv("NETHVOICE_MIDDLEWARE_V1_API_PATH")
	os.Unsetenv("NETHVOICE_MIDDLEWARE_V1_WS_PATH")
	os.Unsetenv("NETHVOICE_MIDDLEWARE_SECRET_JWT")
	os.Unsetenv("NETHVOICE_MIDDLEWARE_SECRETS_DIR")
	os.Unsetenv("NETHVOICE_MIDDLEWARE_ISSUER_2FA")
	os.Unsetenv("NETHVOICE_MIDDLEWARE_SENSITIVE_LIST")
}

// Helper function to reset test state between tests
func resetTestState() {
	// Clear user sessions and test files to ensure isolation between tests
	store.UserSessions = make(map[string]*models.UserSession)

	// Clean up any test files
	os.RemoveAll("/tmp/test-secrets")
	os.MkdirAll("/tmp/test-secrets", 0700)
}

// Test successful login with correct credentials
func TestLogin_Success(t *testing.T) {
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

// Test login with invalid credentials
func TestLogin_InvalidCredentials(t *testing.T) {
	resetTestState()

	loginData := map[string]string{
		"username": "wronguser",
		"password": "wrongpass",
	}
	jsonData, _ := json.Marshal(loginData)

	resp, err := http.Post(testServerURL+"/login", "application/json", bytes.NewBuffer(jsonData))
	assert.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// Test login with missing credentials
func TestLogin_MissingCredentials(t *testing.T) {
	resetTestState()

	resp, err := http.Post(testServerURL+"/login", "application/json", bytes.NewBuffer([]byte("{}")))
	assert.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// Test logout endpoint and session cleanup
func TestLogout(t *testing.T) {
	resetTestState()

	// First login to get token
	token := utils.PerformLogin(testServerURL)

	client := &http.Client{}
	req, _ := http.NewRequest("POST", testServerURL+"/logout", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Wait a moment for session cleanup
	time.Sleep(100 * time.Millisecond)

	// Verify session is removed
	assert.Empty(t, store.UserSessions)
}

// Test QR code generation for 2FA setup
func TestQRCode_Generation(t *testing.T) {
	resetTestState()

	// First login to get token
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
	assert.Contains(t, data["url"].(string), "otpauth://totp")
	assert.Contains(t, data["url"].(string), "NetCTI-Test")
}

// Test that 2FA is initially disabled for a new user
func Test2FAStatus_Initially_Disabled(t *testing.T) {
	resetTestState()

	// First login to get token
	token := utils.PerformLogin(testServerURL)

	client := &http.Client{}
	req, _ := http.NewRequest("GET", testServerURL+"/2fa", nil)
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

// Test OTP verification with an invalid OTP code
func TestOTPVerify_InvalidOTP(t *testing.T) {
	resetTestState()

	// Setup 2FA for user
	utils.Setup2FA("testuser")

	otpData := map[string]string{
		"username": "testuser",
		"otp":      "123456", // Invalid OTP
	}
	jsonData, _ := json.Marshal(otpData)

	resp, err := http.Post(testServerURL+"/2fa/otp-verify", "application/json", bytes.NewBuffer(jsonData))
	assert.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var response map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&response)
	assert.NoError(t, err)
	assert.Equal(t, "validation_failed", response["message"])
}

// Test OTP verification for a non-existent user
func TestOTPVerify_UserNotFound(t *testing.T) {
	resetTestState()

	otpData := map[string]string{
		"username": "nonexistent",
		"otp":      "123456",
	}
	jsonData, _ := json.Marshal(otpData)

	resp, err := http.Post(testServerURL+"/2fa/otp-verify", "application/json", bytes.NewBuffer(jsonData))
	assert.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// Test recovery codes generation for 2FA
func TestRecoveryCodes_Generation(t *testing.T) {
	resetTestState()

	// First login and setup 2FA
	token := utils.PerformLogin(testServerURL)
	utils.Setup2FA("testuser")

	client := &http.Client{}
	req, _ := http.NewRequest("GET", testServerURL+"/2fa/recovery-codes", nil)
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

// Test disabling 2FA and receiving a new token
func TestDisable2FA(t *testing.T) {
	resetTestState()

	// First login and setup 2FA
	token := utils.PerformLogin(testServerURL)
	utils.Setup2FA("testuser")
	utils.Enable2FA("testuser")

	client := &http.Client{}
	req, _ := http.NewRequest("DELETE", testServerURL+"/2fa", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var response map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&response)
	assert.NoError(t, err)
	assert.Equal(t, "2FA revocate successfully", response["message"])

	// Check that new token is provided
	data := response["data"].(map[string]interface{})
	assert.NotEmpty(t, data["token"])
}

// Test that unauthorized access is denied
func TestUnauthorizedAccess(t *testing.T) {
	resetTestState()

	client := &http.Client{}
	req, _ := http.NewRequest("GET", testServerURL+"/2fa", nil)

	resp, err := client.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// Test OTP verification using a recovery code
func TestOTPVerify_WithRecoveryCode(t *testing.T) {
	resetTestState()

	// Setup 2FA for user
	utils.Setup2FA("testuser")
	utils.Enable2FA("testuser")

	// First login to establish session context
	token := utils.PerformLogin(testServerURL)

	// Create recovery codes file
	userDir := "/tmp/test-secrets/testuser"
	codesFile := userDir + "/codes"
	recoveryCode := "12345678"
	os.WriteFile(codesFile, []byte(recoveryCode+"\n87654321\n"), 0600)

	otpData := map[string]string{
		"username": "testuser",
		"otp":      recoveryCode,
	}
	jsonData, _ := json.Marshal(otpData)

	client := &http.Client{}
	req, _ := http.NewRequest("POST", testServerURL+"/2fa/otp-verify", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var response map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&response)
	assert.NoError(t, err)
	assert.Equal(t, "OTP verified", response["message"])

	// Verify recovery code was removed
	remainingCodes, _ := os.ReadFile(codesFile)
	assert.NotContains(t, string(remainingCodes), recoveryCode)
	assert.Contains(t, string(remainingCodes), "87654321")
}

// Test that access is forbidden if 2FA is enabled but OTP is not verified
func TestAuth_With2FAEnabled_WithoutOTPVerification(t *testing.T) {
	resetTestState()

	// Setup and enable 2FA for user
	utils.Setup2FA("testuser")
	utils.Enable2FA("testuser")

	// Login (this should succeed but user session will have OTP_Verified = false)
	token := utils.PerformLogin(testServerURL)

	// Try to access protected endpoint without OTP verification
	client := &http.Client{}
	req, _ := http.NewRequest("GET", testServerURL+"/health", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()

	// Should be forbidden because 2FA is enabled but OTP not verified
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

// Test malformed OTP verification request
func TestMalformedOTPRequest(t *testing.T) {
	resetTestState()

	resp, err := http.Post(testServerURL+"/2fa/otp-verify", "application/json", bytes.NewBuffer([]byte("invalid json")))
	assert.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var response map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&response)
	assert.NoError(t, err)
	assert.Equal(t, "request fields malformed", response["message"])
}

// Test login with 2FA enabled and required for user
func TestLogin_With2FAEnabled_Required(t *testing.T) {
	resetTestState()

	// Enable 2FA for the user
	utils.Setup2FA("testuser")
	utils.Enable2FA("testuser")

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

	// Decode JWT and check "2fa" claim
	tokenString := response["token"].(string)
	parts := strings.Split(tokenString, ".")
	assert.Equal(t, 3, len(parts), "JWT should have 3 parts")

	payload, err := utils.DecodeJWTPart(parts[1])
	fmt.Println("Decoded payload:", string(payload))
	assert.NoError(t, err)
	var claims map[string]interface{}
	err = json.Unmarshal(payload, &claims)
	assert.NoError(t, err)
	assert.True(t, claims["2fa"].(bool))

	// Try to access a protected resource: should be forbidden
	client := &http.Client{}
	req, _ := http.NewRequest("GET", testServerURL+"/health", nil)
	req.Header.Set("Authorization", "Bearer "+response["token"].(string))
	protectedResp, err := client.Do(req)
	assert.NoError(t, err)
	defer protectedResp.Body.Close()
	assert.Equal(t, http.StatusForbidden, protectedResp.StatusCode)
}
