/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package main

import (
	"bytes"
	"encoding/json"
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
	os.Setenv("NETHVOICE_MIDDLEWARE_V1_WS_ENDPOINT", mockURL)
	os.Setenv("NETHVOICE_MIDDLEWARE_V1_API_PATH", "/webrest")
	os.Setenv("NETHVOICE_MIDDLEWARE_V1_WS_PATH", "/socket.io")
	os.Setenv("NETHVOICE_MIDDLEWARE_SECRETS_DIR", "/tmp/test-secrets/nethcti")
	os.Setenv("NETHVOICE_MIDDLEWARE_ISSUER_2FA", "NetCTI-Test")
	os.Setenv("NETHVOICE_MIDDLEWARE_SENSITIVE_LIST", "password,secret")

	// Set database environment variables for testing
	os.Setenv("NETHVOICE_MIDDLEWARE_MARIADB_HOST", "127.0.0.1")
	os.Setenv("NETHVOICE_MIDDLEWARE_MARIADB_PORT", "3306")
	os.Setenv("NETHVOICE_MIDDLEWARE_MARIADB_USER", "root")
	os.Setenv("NETHVOICE_MIDDLEWARE_MARIADB_PASSWORD", "root")
	os.Setenv("NETHVOICE_MIDDLEWARE_MARIADB_DATABASE", "nethcti3")
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
	// This mock server simulates the NetCTI backend for authentication and user info
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/webrest/authentication/login":
			var loginData map[string]string
			json.NewDecoder(r.Body).Decode(&loginData)

			// Simulate Digest authentication challenge for correct credentials
			if loginData["username"] == "testuser" && loginData["password"] == "testpass" {
				w.Header().Set("Www-Authenticate", `Digest realm="test", nonce="test123", qop="auth"`)
				w.WriteHeader(http.StatusUnauthorized)
			} else {
				w.WriteHeader(http.StatusUnauthorized)
			}
		case "/webrest/user/me":
			auth := r.Header.Get("Authorization")
			if strings.Contains(auth, "testuser") {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"username": "testuser"}`))
			} else {
				w.WriteHeader(http.StatusUnauthorized)
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
