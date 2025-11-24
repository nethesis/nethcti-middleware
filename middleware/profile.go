/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package middleware

import (
	"fmt"
	"net/http"
	"time"

	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"
	jwtv4 "github.com/golang-jwt/jwt/v4"

	"github.com/nethesis/nethcti-middleware/configuration"
	"github.com/nethesis/nethcti-middleware/logs"
	"github.com/nethesis/nethcti-middleware/methods"
	"github.com/nethesis/nethcti-middleware/models"
	"github.com/nethesis/nethcti-middleware/store"
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

// RegenerateTokenWithClaims creates a new JWT token with fresh profile data for an existing user session
func RegenerateTokenWithClaims(userSession *models.UserSession, oldToken string) (string, time.Time, error) {
	// Create new JWT payload with fresh capabilities from profile
	status, _ := methods.GetUserStatus(userSession.Username)

	now := time.Now()
	expire := now.Add(time.Hour * 24 * 14) // 2 weeks

	// Load fresh profile data
	profile, err := store.GetUserProfile(userSession.Username)
	if err != nil {
		logs.Log(fmt.Sprintf("[AUTHZ][WARN] Failed to load profile for reload token for user %s: %v", userSession.Username, err))
		profile = &store.ProfileData{
			ID:           "",
			Name:         "",
			Capabilities: make(map[string]bool),
		}
	}

	// Build claims with fresh capabilities
	claims := jwtv4.MapClaims{
		"id":           userSession.Username,
		"2fa":          status == "1",
		"otp_verified": userSession.OTP_Verified,
		"exp":          expire.Unix(),
		"iat":          now.Unix(),
		"profile_id":   profile.ID,
		"profile_name": profile.Name,
	}

	// Inject all fresh capabilities
	for capability, value := range profile.Capabilities {
		claims[capability] = value
	}

	// Create and sign token
	token := jwtv4.NewWithClaims(jwtv4.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(configuration.Config.Secret_jwt))
	if err != nil {
		return "", time.Time{}, err
	}

	// Find and replace the old token in the array
	for i, t := range userSession.JWTTokens {
		if t == oldToken {
			userSession.JWTTokens[i] = tokenString
			break
		}
	}

	// Save sessions to disk
	if err := store.SaveSessions(); err != nil {
		logs.Log(fmt.Sprintf("[ERROR][AUTH] Failed to save sessions after token regeneration: %v", err))
		return "", time.Time{}, err
	}

	logs.Log(fmt.Sprintf("[AUTHZ] Regenerated JWT token for user %s with %d capabilities (profile: %s)",
		userSession.Username, len(profile.Capabilities), profile.Name))

	return tokenString, expire, nil
}
