/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package methods

import (
	"io"
	"net/http"
	"strings"
	"time"

	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"

	"github.com/nethesis/nethcti-middleware/audit"
	"github.com/nethesis/nethcti-middleware/configuration"
	"github.com/nethesis/nethcti-middleware/middleware"
	"github.com/nethesis/nethcti-middleware/models"
	"github.com/nethesis/nethcti-middleware/utils"
)

// ProxyV1Request forwards requests to the legacy V1 API
func ProxyV1Request(c *gin.Context, path string) {
	// Check if V1 endpoint is configured
	if configuration.Config.V1Endpoint == "" {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"code":    503,
			"message": "V1 API endpoint not configured",
		})
		return
	}

	// Extract path from the original request
	if path == "" {
		path = "/"
	}

	// Build the forwarding URL
	url := configuration.Config.V1Endpoint + configuration.Config.V1Path + path

	// Create a new request
	req, err := http.NewRequest(c.Request.Method, url, c.Request.Body)
	if err != nil {
		utils.LogError(errors.Wrap(err, "failed to create proxy request"))
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":    500,
			"message": "Failed to forward request",
		})
		return
	}

	// Copy headers from the original request
	for name, values := range c.Request.Header {
		// Skip the Host header to avoid conflicts
		if strings.ToLower(name) == "host" {
			continue
		}
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}

	// Retrieve the UserSession associated with the current JWT token
	JWTToken := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
	if JWTToken == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"code":    401,
			"message": "Authorization token not provided",
		})
		return
	}

	userSession, exists := middleware.UserSessions[JWTToken]
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"code":    401,
			"message": "User session not found",
		})
		return
	}

	// Add the NetCTI token to the request headers
	req.Header.Set("Authorization", userSession.NetCTIToken)

	// Copy query parameters
	req.URL.RawQuery = c.Request.URL.RawQuery

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: time.Second * 30,
	}

	// Forward the request
	resp, err := client.Do(req)
	if err != nil {
		utils.LogError(errors.Wrap(err, "failed to forward request to V1 API"))
		c.JSON(http.StatusBadGateway, gin.H{
			"code":    502,
			"message": "Failed to reach V1 API",
		})
		return
	}
	defer resp.Body.Close()

	// Extract claims from the JWT token
	claims := jwt.ExtractClaims(c)

	// Log the proxy action
	auditData := models.Audit{
		User:      claims["id"].(string),
		Action:    "proxy-v1-request",
		Data:      path,
		Timestamp: time.Now().UTC(),
	}
	audit.Store(auditData)

	// Copy response headers
	for name, values := range resp.Header {
		for _, value := range values {
			c.Header(name, value)
		}
	}

	// Set response status code
	c.Status(resp.StatusCode)

	// Copy response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		utils.LogError(errors.Wrap(err, "failed to read V1 API response"))
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":    500,
			"message": "Failed to process V1 API response",
		})
		return
	}

	// Write response body
	c.Writer.Write(body)
}
