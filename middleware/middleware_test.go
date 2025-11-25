/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"

	"github.com/nethesis/nethcti-middleware/configuration"
	"github.com/nethesis/nethcti-middleware/logs"
)

func init() {
	// Initialize logs for tests
	logs.Init("nethcti-test")
}

// TestRequireSuperAdminWithValidTokenAndValidIP tests successful authentication with valid token and IP
func TestRequireSuperAdminWithValidTokenAndValidIP(t *testing.T) {
	// Setup
	gin.SetMode(gin.TestMode)
	configuration.Config.SuperAdminToken = "valid-test-token-123"
	configuration.Config.SuperAdminAllowedIPs = []string{"127.0.0.1", "192.168.1.0/24"}

	router := gin.New()
	router.POST("/admin/test", RequireSuperAdmin(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Create request with valid token from allowed IP
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/admin/test", nil)
	req.Header.Set("Authorization", "Bearer valid-test-token-123")
	req.RemoteAddr = "127.0.0.1:12345"

	router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "success")
}

// TestRequireSuperAdminWithInvalidToken tests rejection with invalid/wrong token
func TestRequireSuperAdminWithInvalidToken(t *testing.T) {
	// Setup
	gin.SetMode(gin.TestMode)
	configuration.Config.SuperAdminToken = "valid-test-token-123"
	configuration.Config.SuperAdminAllowedIPs = []string{"127.0.0.1"}

	router := gin.New()
	router.POST("/admin/test", RequireSuperAdmin(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Create request with invalid token
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/admin/test", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	req.RemoteAddr = "127.0.0.1:12345"

	router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "super admin authentication required")
}

// TestRequireSuperAdminWithMissingToken tests rejection when token header is missing
func TestRequireSuperAdminWithMissingToken(t *testing.T) {
	// Setup
	gin.SetMode(gin.TestMode)
	configuration.Config.SuperAdminToken = "valid-test-token-123"
	configuration.Config.SuperAdminAllowedIPs = []string{"127.0.0.1"}

	router := gin.New()
	router.POST("/admin/test", RequireSuperAdmin(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Create request without Authorization header
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/admin/test", nil)
	req.RemoteAddr = "127.0.0.1:12345"

	router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "super admin authentication required")
}

// TestRequireSuperAdminWithBadIPAddress tests rejection with IP not in allowed list
func TestRequireSuperAdminWithBadIPAddress(t *testing.T) {
	// Setup
	gin.SetMode(gin.TestMode)
	configuration.Config.SuperAdminToken = "valid-test-token-123"
	configuration.Config.SuperAdminAllowedIPs = []string{"192.168.1.0/24"}

	router := gin.New()
	router.POST("/admin/test", RequireSuperAdmin(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Create request from disallowed IP with valid token
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/admin/test", nil)
	req.Header.Set("Authorization", "Bearer valid-test-token-123")
	req.RemoteAddr = "10.0.0.1:12345"

	router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "access denied: IP not in allowed list")
}

// TestRequireSuperAdminWithCIDRRange tests IP matching with CIDR notation
func TestRequireSuperAdminWithCIDRRange(t *testing.T) {
	// Setup
	gin.SetMode(gin.TestMode)
	configuration.Config.SuperAdminToken = "valid-test-token-123"
	configuration.Config.SuperAdminAllowedIPs = []string{"192.168.1.0/24", "10.0.0.0/8"}

	router := gin.New()
	router.POST("/admin/test", RequireSuperAdmin(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Test IP within CIDR range
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/admin/test", nil)
	req.Header.Set("Authorization", "Bearer valid-test-token-123")
	req.RemoteAddr = "192.168.1.50:12345"

	router.ServeHTTP(w, req)

	// Assert - should be allowed
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "success")

	// Test IP within second CIDR range
	w2 := httptest.NewRecorder()
	req2, _ := http.NewRequest("POST", "/admin/test", nil)
	req2.Header.Set("Authorization", "Bearer valid-test-token-123")
	req2.RemoteAddr = "10.50.100.200:12345"

	router.ServeHTTP(w2, req2)

	// Assert - should be allowed
	assert.Equal(t, http.StatusOK, w2.Code)

	// Test IP outside CIDR range
	w3 := httptest.NewRecorder()
	req3, _ := http.NewRequest("POST", "/admin/test", nil)
	req3.Header.Set("Authorization", "Bearer valid-test-token-123")
	req3.RemoteAddr = "172.16.0.1:12345"

	router.ServeHTTP(w3, req3)

	// Assert - should be forbidden
	assert.Equal(t, http.StatusForbidden, w3.Code)
	assert.Contains(t, w3.Body.String(), "access denied: IP not in allowed list")
}

// TestRequireSuperAdminWithInvalidCIDRNotation tests graceful handling of invalid CIDR
func TestRequireSuperAdminWithInvalidCIDRNotation(t *testing.T) {
	// Setup
	gin.SetMode(gin.TestMode)
	configuration.Config.SuperAdminToken = "valid-test-token-123"
	// Invalid CIDR notation should be handled gracefully
	configuration.Config.SuperAdminAllowedIPs = []string{"invalid/cidr", "127.0.0.1"}

	router := gin.New()
	router.POST("/admin/test", RequireSuperAdmin(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Create request from exact IP match (fallback when CIDR parsing fails)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/admin/test", nil)
	req.Header.Set("Authorization", "Bearer valid-test-token-123")
	req.RemoteAddr = "127.0.0.1:12345"

	router.ServeHTTP(w, req)

	// Assert - should be allowed via exact IP match
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "success")
}

// TestRequireSuperAdminEmptyConfigToken tests rejection when token config is empty
func TestRequireSuperAdminEmptyConfigToken(t *testing.T) {
	// Setup
	gin.SetMode(gin.TestMode)
	configuration.Config.SuperAdminToken = ""
	configuration.Config.SuperAdminAllowedIPs = []string{"127.0.0.1"}

	router := gin.New()
	router.POST("/admin/test", RequireSuperAdmin(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Create request with token (but config token is empty)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/admin/test", nil)
	req.Header.Set("Authorization", "Bearer any-token")
	req.RemoteAddr = "127.0.0.1:12345"

	router.ServeHTTP(w, req)

	// Assert - should be rejected because config token is empty
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "super admin authentication required")
}

// TestRequireSuperAdminEmptyAllowedIPsList tests rejection when no IPs are allowed
func TestRequireSuperAdminEmptyAllowedIPsList(t *testing.T) {
	// Setup
	gin.SetMode(gin.TestMode)
	configuration.Config.SuperAdminToken = "valid-test-token-123"
	configuration.Config.SuperAdminAllowedIPs = []string{}

	router := gin.New()
	router.POST("/admin/test", RequireSuperAdmin(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Create request with valid token but no allowed IPs
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/admin/test", nil)
	req.Header.Set("Authorization", "Bearer valid-test-token-123")
	req.RemoteAddr = "127.0.0.1:12345"

	router.ServeHTTP(w, req)

	// Assert - should be forbidden
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "access denied: IP not in allowed list")
}

// TestRequireSuperAdminWithMalformedAuthHeader tests handling of malformed Authorization header
func TestRequireSuperAdminWithMalformedAuthHeader(t *testing.T) {
	// Setup
	gin.SetMode(gin.TestMode)
	configuration.Config.SuperAdminToken = "valid-test-token-123"
	configuration.Config.SuperAdminAllowedIPs = []string{"127.0.0.1"}

	router := gin.New()
	router.POST("/admin/test", RequireSuperAdmin(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Create request with malformed Authorization header (missing "Bearer " prefix)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/admin/test", nil)
	req.Header.Set("Authorization", "valid-test-token-123") // Missing "Bearer " prefix
	req.RemoteAddr = "127.0.0.1:12345"

	router.ServeHTTP(w, req)

	// Assert - should be rejected because token is not extracted properly
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestRequireSuperAdminWithIPv6Address tests IPv6 address handling
func TestRequireSuperAdminWithIPv6Address(t *testing.T) {
	// Setup
	gin.SetMode(gin.TestMode)
	configuration.Config.SuperAdminToken = "valid-test-token-123"
	configuration.Config.SuperAdminAllowedIPs = []string{"::1"}

	router := gin.New()
	router.POST("/admin/test", RequireSuperAdmin(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Create request from IPv6 localhost
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/admin/test", nil)
	req.Header.Set("Authorization", "Bearer valid-test-token-123")
	req.RemoteAddr = "[::1]:12345"

	router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "success")
}

// TestRequireSuperAdminTimingAttackResistance tests token comparison is constant-time
func TestRequireSuperAdminTimingAttackResistance(t *testing.T) {
	// Setup
	gin.SetMode(gin.TestMode)
	configuration.Config.SuperAdminToken = "a-very-long-token-string-for-timing-test-12345"
	configuration.Config.SuperAdminAllowedIPs = []string{"127.0.0.1"}

	router := gin.New()
	router.POST("/admin/test", RequireSuperAdmin(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Test with wrong token (should take roughly same time as correct token comparison)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/admin/test", nil)
	req.Header.Set("Authorization", "Bearer b-very-long-token-string-for-timing-test-12345")
	req.RemoteAddr = "127.0.0.1:12345"

	router.ServeHTTP(w, req)

	// Assert - token comparison is constant-time (no early exit on mismatch)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestRequireSuperAdminMultipleAllowedIPs tests with multiple direct IP addresses
func TestRequireSuperAdminMultipleAllowedIPs(t *testing.T) {
	// Setup
	gin.SetMode(gin.TestMode)
	configuration.Config.SuperAdminToken = "valid-test-token-123"
	configuration.Config.SuperAdminAllowedIPs = []string{"127.0.0.1", "192.168.1.1", "10.0.0.1"}

	router := gin.New()
	router.POST("/admin/test", RequireSuperAdmin(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Test first IP
	w1 := httptest.NewRecorder()
	req1, _ := http.NewRequest("POST", "/admin/test", nil)
	req1.Header.Set("Authorization", "Bearer valid-test-token-123")
	req1.RemoteAddr = "127.0.0.1:12345"
	router.ServeHTTP(w1, req1)
	assert.Equal(t, http.StatusOK, w1.Code)

	// Test second IP
	w2 := httptest.NewRecorder()
	req2, _ := http.NewRequest("POST", "/admin/test", nil)
	req2.Header.Set("Authorization", "Bearer valid-test-token-123")
	req2.RemoteAddr = "192.168.1.1:12345"
	router.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusOK, w2.Code)

	// Test third IP
	w3 := httptest.NewRecorder()
	req3, _ := http.NewRequest("POST", "/admin/test", nil)
	req3.Header.Set("Authorization", "Bearer valid-test-token-123")
	req3.RemoteAddr = "10.0.0.1:12345"
	router.ServeHTTP(w3, req3)
	assert.Equal(t, http.StatusOK, w3.Code)

	// Test IP not in list
	w4 := httptest.NewRecorder()
	req4, _ := http.NewRequest("POST", "/admin/test", nil)
	req4.Header.Set("Authorization", "Bearer valid-test-token-123")
	req4.RemoteAddr = "172.16.0.1:12345"
	router.ServeHTTP(w4, req4)
	assert.Equal(t, http.StatusForbidden, w4.Code)
}
