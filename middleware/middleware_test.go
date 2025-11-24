/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package middleware

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"

	"github.com/nethesis/nethcti-middleware/configuration"
	"github.com/nethesis/nethcti-middleware/logs"
)

func init() {
	logs.Init("super-admin-tests")
}

// setupSuperAdminTestDefaults sets up default configuration for super admin tests
func setupSuperAdminTestDefaults() {
	// Set default allowed IPs to localhost
	configuration.Config.SuperAdminAllowedIPs = []string{"127.0.0.0/8"}
	configuration.Config.SuperAdminToken = "test-token"
}

// TestRequireSuperAdminValidToken verifies that valid bearer token passes authentication
func TestRequireSuperAdminValidToken(t *testing.T) {
	setupSuperAdminTestDefaults()

	// Setup: Create test token
	testToken := "test-super-admin-token-12345"

	// Set configuration
	configuration.Config.SuperAdminToken = testToken
	configuration.Config.SuperAdminAllowedIPs = []string{"127.0.0.0/8"}

	// Create test context
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("POST", "/admin/reload", nil)
	c.Request.RemoteAddr = "127.0.0.1:12345" // localhost IP
	c.Request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", testToken))

	// Apply middleware
	handler := RequireSuperAdmin()
	handler(c)

	// Assertions
	assert.False(t, c.IsAborted(), "request with valid token should not be aborted")
	assert.Equal(t, http.StatusOK, w.Code, "should not set error status for valid token")
}

// TestRequireSuperAdminInvalidToken verifies that invalid bearer token is rejected
func TestRequireSuperAdminInvalidToken(t *testing.T) {
	setupSuperAdminTestDefaults()

	// Setup
	validToken := "valid-token-12345"
	invalidToken := "invalid-token-67890"
	configuration.Config.SuperAdminToken = validToken
	configuration.Config.SuperAdminAllowedIPs = []string{"127.0.0.0/8"}

	// Create test context with invalid token
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("POST", "/admin/reload", nil)
	c.Request.RemoteAddr = "127.0.0.1:12345" // localhost IP
	c.Request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", invalidToken))

	// Apply middleware
	handler := RequireSuperAdmin()
	handler(c)

	// Assertions
	assert.True(t, c.IsAborted(), "request with invalid token should be aborted")
	assert.Equal(t, http.StatusUnauthorized, w.Code, "should return 401 for invalid token")
}

// TestRequireSuperAdminMissingAuthHeader verifies that missing Authorization header is rejected
func TestRequireSuperAdminMissingAuthHeader(t *testing.T) {
	setupSuperAdminTestDefaults()

	// Setup
	configuration.Config.SuperAdminToken = "valid-token"
	configuration.Config.SuperAdminAllowedIPs = []string{"127.0.0.0/8"}

	// Create test context without Authorization header
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("POST", "/admin/reload", nil)
	c.Request.RemoteAddr = "127.0.0.1:12345" // localhost IP
	// No Authorization header set

	// Apply middleware
	handler := RequireSuperAdmin()
	handler(c)

	// Assertions
	assert.True(t, c.IsAborted(), "request without auth header should be aborted")
	assert.Equal(t, http.StatusUnauthorized, w.Code, "should return 401 for missing auth header")
}

// TestRequireSuperAdminEmptyAuthHeader verifies that empty Authorization header is rejected
func TestRequireSuperAdminEmptyAuthHeader(t *testing.T) {
	setupSuperAdminTestDefaults()

	// Setup
	configuration.Config.SuperAdminToken = "valid-token"
	configuration.Config.SuperAdminAllowedIPs = []string{"127.0.0.0/8"}

	// Create test context with empty Authorization header
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("POST", "/admin/reload", nil)
	c.Request.RemoteAddr = "127.0.0.1:12345" // localhost IP
	c.Request.Header.Set("Authorization", "")

	// Apply middleware
	handler := RequireSuperAdmin()
	handler(c)

	// Assertions
	assert.True(t, c.IsAborted(), "request with empty auth header should be aborted")
	assert.Equal(t, http.StatusUnauthorized, w.Code, "should return 401 for empty auth header")
}

// TestRequireSuperAdminMalformedAuthHeader verifies that malformed Bearer token is rejected
func TestRequireSuperAdminMalformedAuthHeader(t *testing.T) {
	setupSuperAdminTestDefaults()

	// Setup
	configuration.Config.SuperAdminToken = "valid-token"
	configuration.Config.SuperAdminAllowedIPs = []string{"127.0.0.0/8"}

	// Create test context with malformed auth header (missing "Bearer ")
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("POST", "/admin/reload", nil)
	c.Request.RemoteAddr = "127.0.0.1:12345" // localhost IP
	c.Request.Header.Set("Authorization", "InvalidToken12345")

	// Apply middleware
	handler := RequireSuperAdmin()
	handler(c)

	// Assertions
	assert.True(t, c.IsAborted(), "request with malformed auth header should be aborted")
	assert.Equal(t, http.StatusUnauthorized, w.Code, "should return 401 for malformed auth header")
}

// TestRequireSuperAdminEmptyConfigToken verifies that empty configuration token rejects all requests
func TestRequireSuperAdminEmptyConfigToken(t *testing.T) {
	// Setup
	configuration.Config.SuperAdminToken = ""

	// Create test context
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("POST", "/admin/reload", nil)
	c.Request.RemoteAddr = "127.0.0.1:12345" // localhost IP
	c.Request.Header.Set("Authorization", "Bearer any-token")

	// Apply middleware
	handler := RequireSuperAdmin()
	handler(c)

	// Assertions
	assert.True(t, c.IsAborted(), "request should be aborted when config token is empty")
	assert.Equal(t, http.StatusUnauthorized, w.Code, "should return 401 when config token is empty")
}

// TestRequireSuperAdminConstantTimeComparison verifies timing attack resistance
func TestRequireSuperAdminConstantTimeComparison(t *testing.T) {
	setupSuperAdminTestDefaults()

	// Setup
	validToken := "this-is-a-valid-token-for-testing"
	configuration.Config.SuperAdminToken = validToken
	configuration.Config.SuperAdminAllowedIPs = []string{"127.0.0.0/8"}

	// Test case 1: Token matches at first character but fails later
	w1 := httptest.NewRecorder()
	c1, _ := gin.CreateTestContext(w1)
	c1.Request, _ = http.NewRequest("POST", "/admin/reload", nil)
	c1.Request.RemoteAddr = "127.0.0.1:12345" // localhost IP
	c1.Request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", "this-is-a-different-token"))

	handler := RequireSuperAdmin()
	handler(c1)
	assert.True(t, c1.IsAborted(), "token with same prefix should fail")
	assert.Equal(t, http.StatusUnauthorized, w1.Code)

	// Test case 2: Token completely different from the start
	w2 := httptest.NewRecorder()
	c2, _ := gin.CreateTestContext(w2)
	c2.Request, _ = http.NewRequest("POST", "/admin/reload", nil)
	c2.Request.RemoteAddr = "127.0.0.1:12345" // localhost IP
	c2.Request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", "completely-different-token"))

	handler(c2)
	assert.True(t, c2.IsAborted(), "completely different token should fail")
	assert.Equal(t, http.StatusUnauthorized, w2.Code)
}

// TestRequireSuperAdminBearerCaseInsensitive verifies Bearer scheme is case-sensitive
func TestRequireSuperAdminBearerCaseSensitive(t *testing.T) {
	setupSuperAdminTestDefaults()

	// Setup
	configuration.Config.SuperAdminToken = "valid-token"
	configuration.Config.SuperAdminAllowedIPs = []string{"127.0.0.0/8"}

	// Create test context with lowercase "bearer" (should fail)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("POST", "/admin/reload", nil)
	c.Request.RemoteAddr = "127.0.0.1:12345" // localhost IP
	c.Request.Header.Set("Authorization", "bearer valid-token")

	// Apply middleware
	handler := RequireSuperAdmin()
	handler(c)

	// Assertions - lowercase "bearer" should not be accepted
	assert.True(t, c.IsAborted(), "lowercase 'bearer' should not be accepted")
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestRequireSuperAdminExtraWhitespace verifies Bearer token parsing
func TestRequireSuperAdminExtraWhitespace(t *testing.T) {
	setupSuperAdminTestDefaults()

	// Setup
	validToken := "valid-token"
	configuration.Config.SuperAdminToken = validToken
	configuration.Config.SuperAdminAllowedIPs = []string{"127.0.0.0/8"}

	// Create test context with extra spaces (should fail - strict parsing)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("POST", "/admin/reload", nil)
	c.Request.RemoteAddr = "127.0.0.1:12345"                     // localhost IP
	c.Request.Header.Set("Authorization", "Bearer  valid-token") // double space

	// Apply middleware
	handler := RequireSuperAdmin()
	handler(c)

	// Assertions - extra space should cause mismatch
	assert.True(t, c.IsAborted(), "extra whitespace should cause token mismatch")
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestRequireSuperAdminContinuationAfterSuccess verifies Next() is called on success
func TestRequireSuperAdminContinuationAfterSuccess(t *testing.T) {
	setupSuperAdminTestDefaults()

	// Setup
	validToken := "test-token-123"
	configuration.Config.SuperAdminToken = validToken
	configuration.Config.SuperAdminAllowedIPs = []string{"127.0.0.0/8"}

	// Create test context with valid token
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("POST", "/admin/reload", nil)
	c.Request.RemoteAddr = "127.0.0.1:12345" // localhost IP
	c.Request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", validToken))

	// Apply middleware
	handler := RequireSuperAdmin()
	handler(c)

	// Assertions - should not abort on valid token
	assert.False(t, c.IsAborted(), "should not abort on valid token")
}

// TestRequireSuperAdminResponseFormat verifies response format on authentication failure
func TestRequireSuperAdminResponseFormat(t *testing.T) {
	setupSuperAdminTestDefaults()

	// Setup
	configuration.Config.SuperAdminToken = "valid-token"
	configuration.Config.SuperAdminAllowedIPs = []string{"127.0.0.0/8"}

	// Create test context with invalid token
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("POST", "/admin/reload", nil)
	c.Request.RemoteAddr = "127.0.0.1:12345" // localhost IP
	c.Request.Header.Set("Authorization", "Bearer invalid-token")

	// Apply middleware
	handler := RequireSuperAdmin()
	handler(c)

	// Assertions
	assert.True(t, c.IsAborted(), "should abort on invalid token")
	assert.Equal(t, http.StatusUnauthorized, w.Code, "should return 401")
	assert.Equal(t, "application/json; charset=utf-8", w.Header().Get("Content-Type"), "should return JSON")

	// Check response body contains expected fields
	assert.Contains(t, w.Body.String(), "code", "response should contain code field")
	assert.Contains(t, w.Body.String(), "message", "response should contain message field")
	assert.Contains(t, w.Body.String(), "super admin authentication required", "response should contain descriptive message")
}

// TestRequireSuperAdminLoadFromFile verifies token loading from file
func TestRequireSuperAdminLoadFromFile(t *testing.T) {
	setupSuperAdminTestDefaults()

	// Create temporary directory and token file
	tmpDir := t.TempDir()
	tokenFile := filepath.Join(tmpDir, "super_admin_token")
	tokenValue := "token-from-file-12345"

	// Write token to file
	err := os.WriteFile(tokenFile, []byte(tokenValue), 0600)
	assert.NoError(t, err, "should be able to write token file")

	// Set configuration to use this token
	configuration.Config.SuperAdminToken = tokenValue
	configuration.Config.SuperAdminAllowedIPs = []string{"127.0.0.0/8"}

	// Create test context with valid token
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("POST", "/admin/reload", nil)
	c.Request.RemoteAddr = "127.0.0.1:12345" // localhost IP
	c.Request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tokenValue))

	// Apply middleware
	handler := RequireSuperAdmin()
	handler(c)

	// Assertions
	assert.False(t, c.IsAborted(), "should authenticate with token loaded from file")
	assert.Equal(t, http.StatusOK, w.Code, "should not set error status")
}

// TestRequireSuperAdminIPWhitelistAllowed verifies that allowed IPs pass authentication
func TestRequireSuperAdminIPWhitelistAllowed(t *testing.T) {
	// Set allowed IPs to localhost range
	configuration.Config.SuperAdminAllowedIPs = []string{"127.0.0.0/8"}
	configuration.Config.SuperAdminToken = "test-token"

	// Create test context with localhost IP
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("POST", "/admin/reload", nil)
	c.Request.RemoteAddr = "127.0.0.1:12345" // localhost IP
	c.Request.Header.Set("Authorization", "Bearer test-token")

	// Apply middleware
	handler := RequireSuperAdmin()
	handler(c)

	// Assertions
	assert.False(t, c.IsAborted(), "should authenticate from allowed IP")
}

// TestRequireSuperAdminIPWhitelistDenied verifies that non-whitelisted IPs are rejected with 403
func TestRequireSuperAdminIPWhitelistDenied(t *testing.T) {
	// Set allowed IPs to localhost range only
	configuration.Config.SuperAdminAllowedIPs = []string{"127.0.0.0/8"}
	configuration.Config.SuperAdminToken = "test-token"

	// Create test context with non-local IP
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("POST", "/admin/reload", nil)
	c.Request.RemoteAddr = "192.168.1.100:12345" // non-localhost IP
	c.Request.Header.Set("Authorization", "Bearer test-token")

	// Apply middleware
	handler := RequireSuperAdmin()
	handler(c)

	// Assertions
	assert.True(t, c.IsAborted(), "should reject non-whitelisted IP")
	assert.Equal(t, http.StatusForbidden, w.Code, "should return 403 Forbidden for disallowed IP")
	assert.Contains(t, w.Body.String(), "access denied", "response should indicate access denied")
}

// TestRequireSuperAdminIPWhitelistCIDRNotation verifies CIDR range support
func TestRequireSuperAdminIPWhitelistCIDRNotation(t *testing.T) {
	// Set allowed IPs using multiple CIDR ranges
	configuration.Config.SuperAdminAllowedIPs = []string{"10.0.0.0/8", "192.168.0.0/16"}
	configuration.Config.SuperAdminToken = "test-token"

	// Test 1: IP in first range (should pass)
	w1 := httptest.NewRecorder()
	c1, _ := gin.CreateTestContext(w1)
	c1.Request, _ = http.NewRequest("POST", "/admin/reload", nil)
	c1.Request.RemoteAddr = "10.5.10.50:12345"
	c1.Request.Header.Set("Authorization", "Bearer test-token")

	handler := RequireSuperAdmin()
	handler(c1)

	assert.False(t, c1.IsAborted(), "should authenticate from IP in first CIDR range")

	// Test 2: IP in second range (should pass)
	w2 := httptest.NewRecorder()
	c2, _ := gin.CreateTestContext(w2)
	c2.Request, _ = http.NewRequest("POST", "/admin/reload", nil)
	c2.Request.RemoteAddr = "192.168.50.10:12345"
	c2.Request.Header.Set("Authorization", "Bearer test-token")

	handler2 := RequireSuperAdmin()
	handler2(c2)

	assert.False(t, c2.IsAborted(), "should authenticate from IP in second CIDR range")

	// Test 3: IP outside both ranges (should fail)
	w3 := httptest.NewRecorder()
	c3, _ := gin.CreateTestContext(w3)
	c3.Request, _ = http.NewRequest("POST", "/admin/reload", nil)
	c3.Request.RemoteAddr = "172.16.0.1:12345"
	c3.Request.Header.Set("Authorization", "Bearer test-token")

	handler3 := RequireSuperAdmin()
	handler3(c3)

	assert.True(t, c3.IsAborted(), "should reject IP outside CIDR ranges")
	assert.Equal(t, http.StatusForbidden, w3.Code, "should return 403 Forbidden")
}

// TestRequireSuperAdminIPWhitelistSpecificIP verifies specific IP whitelisting
func TestRequireSuperAdminIPWhitelistSpecificIP(t *testing.T) {
	// Set allowed IPs to specific IPs
	configuration.Config.SuperAdminAllowedIPs = []string{"10.0.0.1", "192.168.1.100"}
	configuration.Config.SuperAdminToken = "test-token"

	// Test 1: Exact match (should pass)
	w1 := httptest.NewRecorder()
	c1, _ := gin.CreateTestContext(w1)
	c1.Request, _ = http.NewRequest("POST", "/admin/reload", nil)
	c1.Request.RemoteAddr = "10.0.0.1:12345"
	c1.Request.Header.Set("Authorization", "Bearer test-token")

	handler := RequireSuperAdmin()
	handler(c1)

	assert.False(t, c1.IsAborted(), "should authenticate from exact IP match")

	// Test 2: Different IP in same subnet (should fail)
	w2 := httptest.NewRecorder()
	c2, _ := gin.CreateTestContext(w2)
	c2.Request, _ = http.NewRequest("POST", "/admin/reload", nil)
	c2.Request.RemoteAddr = "10.0.0.2:12345"
	c2.Request.Header.Set("Authorization", "Bearer test-token")

	handler2 := RequireSuperAdmin()
	handler2(c2)

	assert.True(t, c2.IsAborted(), "should reject IP not in specific IP list")
	assert.Equal(t, http.StatusForbidden, w2.Code, "should return 403 Forbidden")
}

// TestRequireSuperAdminIPWhitelistThenToken verifies IP check happens before token check
func TestRequireSuperAdminIPWhitelistThenToken(t *testing.T) {
	// Set allowed IPs to localhost only
	configuration.Config.SuperAdminAllowedIPs = []string{"127.0.0.0/8"}
	configuration.Config.SuperAdminToken = "valid-token"

	// Test: Non-allowed IP with invalid token (should return 403, not 401)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("POST", "/admin/reload", nil)
	c.Request.RemoteAddr = "192.168.1.100:12345" // non-localhost
	c.Request.Header.Set("Authorization", "Bearer invalid-token")

	handler := RequireSuperAdmin()
	handler(c)

	// IP check should happen first, so we should get 403, not 401
	assert.Equal(t, http.StatusForbidden, w.Code, "should return 403 for disallowed IP (before token check)")
	assert.Contains(t, w.Body.String(), "access denied", "response should indicate access denied for IP")
}
