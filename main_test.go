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

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"

	"github.com/nethesis/nethcti-middleware/configuration"
	"github.com/nethesis/nethcti-middleware/logs"
	"github.com/nethesis/nethcti-middleware/methods"
	"github.com/nethesis/nethcti-middleware/middleware"
	"github.com/nethesis/nethcti-middleware/models"
	"github.com/nethesis/nethcti-middleware/store"
)

// Test setup
func setupTest() *gin.Engine {
	gin.SetMode(gin.TestMode)

	// Initialize configuration for testing
	configuration.Config = configuration.Configuration{
		ListenAddress: ":8080",
		V1Protocol:    "http",
		V1ApiEndpoint: "localhost:8080",
		V1ApiPath:     "/webrest",
		V1WsPath:      "/socket.io",
		Secret_jwt:    "test-secret-key-for-jwt-tokens",
		SecretsDir:    "/tmp/test-secrets",
		Issuer2FA:     "NetCTI-Test",
		SensitiveList: []string{"password", "secret"},
	}

	// Initialize logs
	logs.Init("nethcti-middleware-test")

	// Initialize store
	store.UserSessionInit()

	// Create test secrets directory
	os.MkdirAll(configuration.Config.SecretsDir, 0700)

	// Create router
	router := gin.New()
	router.RedirectTrailingSlash = false

	// Setup routes
	api := router.Group("/")
	api.POST("/login", middleware.InstanceJWT().LoginHandler)
	api.POST("/logout", middleware.InstanceJWT().LogoutHandler)
	api.POST("/2fa/otp-verify", methods.OTPVerify)

	api.Use(middleware.InstanceJWT().MiddlewareFunc())
	{
		api.GET("/2fa", methods.Get2FAStatus)
		api.DELETE("/2fa", methods.Disable2FA)
		api.GET("/2fa/recovery-codes", methods.Get2FARecoveryCodes)
		api.GET("/2fa/qr-code", methods.QRCode)
		api.GET("/ping", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "pong"})
		})
	}

	return router
}

// Mock NetCTI server for testing
func mockNetCTIServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/webrest/authentication/login" {
			var loginData map[string]string
			json.NewDecoder(r.Body).Decode(&loginData)

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

// Cleanup test data
func cleanupTest() {
	os.RemoveAll(configuration.Config.SecretsDir)
	store.UserSessions = make(map[string]*models.UserSession)
}

func TestLogin_Success(t *testing.T) {
	router := setupTest()
	defer cleanupTest()

	// Start mock server
	mockServer := mockNetCTIServer()
	defer mockServer.Close()

	// Update config to use mock server
	configuration.Config.V1ApiEndpoint = strings.TrimPrefix(mockServer.URL, "http://")

	loginData := map[string]string{
		"username": "testuser",
		"password": "testpass",
	}
	jsonData, _ := json.Marshal(loginData)

	req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, float64(200), response["code"])
	assert.NotEmpty(t, response["token"])
}

func TestLogin_InvalidCredentials(t *testing.T) {
	router := setupTest()
	defer cleanupTest()

	// Start mock server
	mockServer := mockNetCTIServer()
	defer mockServer.Close()

	// Update config to use mock server
	configuration.Config.V1ApiEndpoint = strings.TrimPrefix(mockServer.URL, "http://")

	loginData := map[string]string{
		"username": "wronguser",
		"password": "wrongpass",
	}
	jsonData, _ := json.Marshal(loginData)

	req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestLogin_MissingCredentials(t *testing.T) {
	router := setupTest()
	defer cleanupTest()

	req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer([]byte("{}")))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestQRCode_Generation(t *testing.T) {
	router := setupTest()
	defer cleanupTest()

	// First login to get token
	token := performLogin(router)

	req, _ := http.NewRequest("GET", "/2fa/qr-code", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)

	data := response["data"].(map[string]interface{})
	assert.NotEmpty(t, data["url"])
	assert.NotEmpty(t, data["key"])
	assert.Contains(t, data["url"].(string), "otpauth://totp")
	assert.Contains(t, data["url"].(string), "NetCTI-Test")
}

func Test2FAStatus_Initially_Disabled(t *testing.T) {
	router := setupTest()
	defer cleanupTest()

	// First login to get token
	token := performLogin(router)

	req, _ := http.NewRequest("GET", "/2fa", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.False(t, response["status"].(bool))
}

func TestOTPVerify_InvalidOTP(t *testing.T) {
	router := setupTest()
	defer cleanupTest()

	// Setup 2FA for user
	setup2FA("testuser")

	otpData := map[string]string{
		"username": "testuser",
		"otp":      "123456", // Invalid OTP
	}
	jsonData, _ := json.Marshal(otpData)

	req, _ := http.NewRequest("POST", "/2fa/otp-verify", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "validation_failed", response["message"])
}

func TestOTPVerify_UserNotFound(t *testing.T) {
	router := setupTest()
	defer cleanupTest()

	otpData := map[string]string{
		"username": "nonexistent",
		"otp":      "123456",
	}
	jsonData, _ := json.Marshal(otpData)

	req, _ := http.NewRequest("POST", "/2fa/otp-verify", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestRecoveryCodes_Generation(t *testing.T) {
	router := setupTest()
	defer cleanupTest()

	// First login and setup 2FA
	token := performLogin(router)
	setup2FA("testuser")

	req, _ := http.NewRequest("GET", "/2fa/recovery-codes", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)

	codes := response["codes"].([]interface{})
	assert.Greater(t, len(codes), 0)
}

func TestDisable2FA(t *testing.T) {
	router := setupTest()
	defer cleanupTest()

	// First login and setup 2FA
	token := performLogin(router)
	setup2FA("testuser")
	enable2FA("testuser")

	req, _ := http.NewRequest("DELETE", "/2fa", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "2FA revocate successfully", response["message"])

	// Check that new token is provided
	data := response["data"].(map[string]interface{})
	assert.NotEmpty(t, data["token"])
}

func TestUnauthorizedAccess(t *testing.T) {
	router := setupTest()
	defer cleanupTest()

	req, _ := http.NewRequest("GET", "/2fa", nil)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestLogout(t *testing.T) {
	router := setupTest()
	defer cleanupTest()

	// First login to get token
	token := performLogin(router)

	req, _ := http.NewRequest("POST", "/logout", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Verify session is removed
	assert.Empty(t, store.UserSessions)
}

func TestPingWithAuth(t *testing.T) {
	router := setupTest()
	defer cleanupTest()

	// First login to get token
	token := performLogin(router)

	req, _ := http.NewRequest("GET", "/ping", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "pong", response["message"])
}

// Helper functions

func performLogin(router *gin.Engine) string {
	// Start mock server
	mockServer := mockNetCTIServer()
	defer mockServer.Close()

	// Update config to use mock server
	configuration.Config.V1ApiEndpoint = strings.TrimPrefix(mockServer.URL, "http://")

	loginData := map[string]string{
		"username": "testuser",
		"password": "testpass",
	}
	jsonData, _ := json.Marshal(loginData)

	req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)
	return response["token"].(string)
}

func setup2FA(username string) {
	// Create user directory
	userDir := configuration.Config.SecretsDir + "/" + username
	os.MkdirAll(userDir, 0700)

	// Create secret file
	secretFile := userDir + "/secret"
	os.WriteFile(secretFile, []byte("JBSWY3DPEHPK3PXP"), 0600)

	// Set initial status to disabled
	statusFile := userDir + "/status"
	os.WriteFile(statusFile, []byte("0"), 0600)
}

func enable2FA(username string) {
	statusFile := configuration.Config.SecretsDir + "/" + username + "/status"
	os.WriteFile(statusFile, []byte("1"), 0600)
}

func TestOTPVerify_WithRecoveryCode(t *testing.T) {
	router := setupTest()
	defer cleanupTest()

	// Setup 2FA for user
	setup2FA("testuser")
	enable2FA("testuser")

	// First login to establish session context
	token := performLogin(router)

	// Create recovery codes file
	userDir := configuration.Config.SecretsDir + "/testuser"
	codesFile := userDir + "/codes"
	recoveryCode := "12345678"
	os.WriteFile(codesFile, []byte(recoveryCode+"\n87654321\n"), 0600)

	otpData := map[string]string{
		"username": "testuser",
		"otp":      recoveryCode,
	}
	jsonData, _ := json.Marshal(otpData)

	req, _ := http.NewRequest("POST", "/2fa/otp-verify", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "OTP verified", response["message"])

	// Verify recovery code was removed
	remainingCodes, _ := os.ReadFile(codesFile)
	assert.NotContains(t, string(remainingCodes), recoveryCode)
	assert.Contains(t, string(remainingCodes), "87654321")
}

func TestAuth_With2FAEnabled_WithoutOTPVerification(t *testing.T) {
	router := setupTest()
	defer cleanupTest()

	// Setup and enable 2FA for user
	setup2FA("testuser")
	enable2FA("testuser")

	// Login (this should succeed but user session will have OTP_Verified = false)
	token := performLogin(router)

	// Try to access protected endpoint without OTP verification
	req, _ := http.NewRequest("GET", "/ping", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Should be forbidden because 2FA is enabled but OTP not verified
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestMalformedOTPRequest(t *testing.T) {
	router := setupTest()
	defer cleanupTest()

	req, _ := http.NewRequest("POST", "/2fa/otp-verify", bytes.NewBuffer([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "request fields malformed", response["message"])
}
