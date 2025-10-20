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
	"github.com/fatih/structs"
	"github.com/gin-gonic/gin"

	"github.com/nethesis/nethcti-middleware/configuration"
	"github.com/nethesis/nethcti-middleware/logs"
	"github.com/nethesis/nethcti-middleware/models"
	"github.com/nethesis/nethcti-middleware/store"
)

// ProxyV1Request forwards requests to the legacy V1 API
func ProxyV1Request(c *gin.Context, path string) {
	// Check if V1 endpoint is configured
	if configuration.Config.V1ApiEndpoint == "" {
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
	url := configuration.Config.V1Protocol + "://" + configuration.Config.V1ApiEndpoint + configuration.Config.V1ApiPath + path

	// Create a new request
	req, err := http.NewRequest(c.Request.Method, url, c.Request.Body)
	if err != nil {
		logs.Log("failed to create proxy request")
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":    500,
			"message": "Failed to forward request",
		})
		return
	}

	// Copy headers from the original request
	for name, values := range c.Request.Header {
		for _, value := range values {
			req.Header.Add(name, value)

			// Set Host header with X-Forwarded-Host only for Tancredi routes
			// This allows nethcti-server to proxy correctly to Tancredi
			// This is a workaround, remove when Tancredi is routed internally in
			// middleware
			if strings.HasPrefix(path, "/tancredi") && name == "X-Forwarded-Host" {
				req.Host = value
			}
		}
	}

	// Check if this is a FreePBX API call (has Authorization-User header)
	authorizationUser := c.GetHeader("Authorization-User")
	isFreePBXCall := authorizationUser != ""

	if isFreePBXCall {
		// For FreePBX calls, don't add Authorization header - the Authorization-User header is enough
		logs.Log("[INFO][PROXY] FreePBX API call for user: " + authorizationUser)
	} else {
		// Regular JWT-based authentication flow
		JWTToken := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
		if JWTToken == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"code":    401,
				"message": "Authorization token not provided",
			})
			return
		}

		// Extract claims from the JWT token
		claims := jwt.ExtractClaims(c)
		username := claims["id"].(string)
		nethCTIToken := ""

		// Check if the request is authenticated with an API key
		if AuthenticateAPIKey(username, JWTToken) {
			// If authenticated with API key, retrieve the Phone Island token
			nethCTIToken, err = GetPhoneIslandToken(JWTToken, false)
			if err != nil {
				logs.Log("[ERROR][AUTH] Failed to retrieve Phone Island token for API key")
				c.JSON(http.StatusUnauthorized, gin.H{
					"code":    401,
					"message": "Failed to retrieve Phone Island token",
				})
				return
			}
		} else {
			// If not authenticated with API key, use the NethCTI token from the user session
			userSession := store.UserSessions[username]
			nethCTIToken = userSession.NethCTIToken
		}

		// Add the NetCTI token to the request headers
		req.Header.Set("Authorization", nethCTIToken)
	}

	// Copy query parameters
	req.URL.RawQuery = c.Request.URL.RawQuery

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: time.Second * 30,
	}

	// Forward the request
	resp, err := client.Do(req)
	if err != nil {
		logs.Log("failed to forward request to V1 API")
		c.JSON(http.StatusBadGateway, gin.H{
			"code":    502,
			"message": "Failed to reach V1 API",
		})
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	for name, values := range resp.Header {
		for _, value := range values {
			c.Header(name, value)
		}
	}

	// Check if V1 API returned 404 and provide a more complete response
	if resp.StatusCode == http.StatusNotFound {
		c.JSON(http.StatusNotFound, structs.Map(models.StatusNotFound{
			Code:    404,
			Message: "API not found",
			Data:    nil,
		}))
		return
	}

	// Set response status code
	c.Status(resp.StatusCode)

	// Copy response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logs.Log("failed to read V1 API response")
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":    500,
			"message": "Failed to process V1 API response",
		})
		return
	}

	// Write response body
	c.Writer.Write(body)
}
