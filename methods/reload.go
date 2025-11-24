/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package methods

import (
	"net/http"
	"strings"
	"time"

	"github.com/fatih/structs"
	"github.com/gin-gonic/gin"
	jwtv4 "github.com/golang-jwt/jwt/v4"

	"github.com/nethesis/nethcti-middleware/configuration"
	"github.com/nethesis/nethcti-middleware/logs"
	"github.com/nethesis/nethcti-middleware/models"
	"github.com/nethesis/nethcti-middleware/store"
)

// ReloadProfileAndToken reloads profiles and regenerates JWT token with fresh capabilities
func ReloadProfileAndToken(c *gin.Context) {
	// Extract username from JWT claims - we need to parse JWT claims without the middleware package
	jwtToken := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")

	// Parse token to get claims
	token, _ := jwtv4.Parse(jwtToken, func(token *jwtv4.Token) (interface{}, error) {
		return []byte(configuration.Config.Secret_jwt), nil
	})

	claims, ok := token.Claims.(jwtv4.MapClaims)
	if !ok {
		c.JSON(http.StatusBadRequest, structs.Map(models.StatusBadRequest{
			Code:    400,
			Message: "invalid token",
			Data:    nil,
		}))
		return
	}

	username, ok := claims["id"].(string)
	if !ok || username == "" {
		c.JSON(http.StatusBadRequest, structs.Map(models.StatusBadRequest{
			Code:    400,
			Message: "invalid user",
			Data:    nil,
		}))
		return
	}

	// Get user session
	userSession, ok := store.UserSessions[username]
	if !ok || userSession == nil {
		logs.Log("[AUTHZ][ERROR] User session not found for " + username)
		c.JSON(http.StatusUnauthorized, structs.Map(models.StatusUnauthorized{
			Code:    401,
			Message: "user session not found",
			Data:    nil,
		}))
		return
	}

	// Regenerate token with fresh profile/capability claims
	status, _ := GetUserStatus(username)

	now := time.Now()
	expire := now.Add(time.Hour * 24 * 14) // 2 weeks

	// Load fresh profile data
	profile, err := store.GetUserProfile(username)
	if err != nil {
		logs.Log("[AUTHZ][WARN] Failed to load profile for reload token for user " + username + ": " + err.Error())
		profile = &store.ProfileData{
			ID:           "",
			Name:         "",
			Capabilities: make(map[string]bool),
		}
	}

	// Build claims with fresh capabilities
	newClaims := jwtv4.MapClaims{
		"id":           username,
		"2fa":          status == "1",
		"otp_verified": userSession.OTP_Verified,
		"exp":          expire.Unix(),
		"iat":          now.Unix(),
		"profile_id":   profile.ID,
		"profile_name": profile.Name,
	}

	// Inject all fresh capabilities
	for capability, value := range profile.Capabilities {
		newClaims[capability] = value
	}

	// Create and sign token
	newToken := jwtv4.NewWithClaims(jwtv4.SigningMethodHS256, newClaims)
	tokenString, err := newToken.SignedString([]byte(configuration.Config.Secret_jwt))
	if err != nil {
		logs.Log("[AUTHZ][ERROR] Failed to sign token for " + username + ": " + err.Error())
		c.JSON(http.StatusInternalServerError, structs.Map(models.StatusInternalServerError{
			Code:    500,
			Message: "failed to regenerate token",
			Data:    err.Error(),
		}))
		return
	}

	// Find and replace the old token in the array
	for i, t := range userSession.JWTTokens {
		if t == jwtToken {
			userSession.JWTTokens[i] = tokenString
			break
		}
	}

	// Save sessions to disk
	if err := store.SaveSessions(); err != nil {
		logs.Log("[ERROR][AUTH] Failed to save sessions after token regeneration: " + err.Error())
		c.JSON(http.StatusInternalServerError, structs.Map(models.StatusInternalServerError{
			Code:    500,
			Message: "failed to save session",
			Data:    err.Error(),
		}))
		return
	}

	logs.Log("[AUTHZ] Profile reload and token regeneration completed for user " + username)

	// Return new token to client
	c.JSON(http.StatusOK, structs.Map(models.StatusOK{
		Code:    200,
		Message: "profile reloaded and token refreshed",
		Data: gin.H{
			"token":  tokenString,
			"expire": expire,
		},
	}))
}

// SuperAdminReload reloads profiles and users globally via super admin API endpoint
func SuperAdminReload(c *gin.Context) {
	// Call store.ReloadProfiles() to reload profiles and users from configuration files
	if err := store.ReloadProfiles(); err != nil {
		logs.Log("[AUTHZ][ERROR] Failed to reload profiles via super admin: " + err.Error())
		c.JSON(http.StatusInternalServerError, structs.Map(models.StatusInternalServerError{
			Code:    http.StatusInternalServerError,
			Message: "failed to reload profiles",
			Data:    err.Error(),
		}))
		return
	}

	// Store a flag to indicate broadcast should be done (will be handled by middleware)
	c.Set("broadcast_reload", true)

	logs.Log("[AUTHZ] Global profile reload completed successfully via /admin/reload endpoint")

	// Return success response
	c.JSON(http.StatusOK, structs.Map(models.StatusOK{
		Code:    200,
		Message: "profiles reloaded successfully",
		Data: gin.H{
			"trigger": "api",
		},
	}))
}
