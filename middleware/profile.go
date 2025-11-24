/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package middleware

import (
	"fmt"
	"net/http"

	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"
	"github.com/nethesis/nethcti-middleware/logs"
)

// RequireCapabilities returns a middleware that enforces capability checks from JWT claims.
// It checks if the user has all required capabilities by inspecting the JWT token claims.
func RequireCapabilities(capabilities ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if len(capabilities) == 0 {
			c.Next()
			return
		}

		claims := jwt.ExtractClaims(c)
		username, _ := claims["id"].(string)
		if username == "" {
			logs.Log(fmt.Sprintf("[AUTHZ][WARN] missing identity on %s %s", c.Request.Method, c.Request.RequestURI))
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"code": http.StatusForbidden, "message": "authorization failed"})
			return
		}

		// Check each required capability in JWT claims
		for _, capability := range capabilities {
			capValue, exists := claims[capability]
			if !exists {
				logs.Log(fmt.Sprintf("[AUTHZ][DENIED] %s missing capability %s (not in claims)", username, capability))
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"code": http.StatusForbidden, "message": "missing capability"})
				return
			}

			// Capability must be true
			capBool, ok := capValue.(bool)
			if !ok || !capBool {
				logs.Log(fmt.Sprintf("[AUTHZ][DENIED] %s capability %s is false or invalid", username, capability))
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"code": http.StatusForbidden, "message": "missing capability"})
				return
			}
		}

		c.Next()
	}
}
