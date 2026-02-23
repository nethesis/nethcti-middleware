/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package methods

import (
	"net/http"
	"strings"
	"time"

	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"
	jwtv5 "github.com/golang-jwt/jwt/v5"

	"github.com/nethesis/nethcti-middleware/configuration"
	"github.com/nethesis/nethcti-middleware/models"
	"github.com/nethesis/nethcti-middleware/store"
)

var allowedIntegrationAudiences = map[string]struct{}{
	"phone-island": {},
	"mobile-app":   {},
	"nethlink":     {},
}

// CreatePersistentToken creates a JWT integration token for the requested audience.
func CreatePersistentToken(c *gin.Context) {
	audience, ok := getAudienceFromRequest(c)
	if !ok {
		return
	}
	issueIntegrationToken(c, audience)
}

// CheckPersistentToken checks if at least one valid integration token exists for the requested audience.
func CheckPersistentToken(c *gin.Context) {
	audience, ok := getAudienceFromRequest(c)
	if !ok {
		return
	}
	checkIntegrationToken(c, audience)
}

// RemovePersistentToken revokes all integration JWTs for the requested audience.
func RemovePersistentToken(c *gin.Context) {
	audience, ok := getAudienceFromRequest(c)
	if !ok {
		return
	}
	revokeIntegrationTokens(c, audience)
}

func issueIntegrationToken(c *gin.Context, audience string) {
	claims := jwt.ExtractClaims(c)
	username, ok := claims["id"].(string)
	if !ok || username == "" {
		c.JSON(http.StatusBadRequest, gin.H{"message": "invalid user"})
		return
	}

	userSession := store.UserSessions[username]
	if userSession == nil || userSession.NethCTIToken == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "user session not found"})
		return
	}

	newClaims := jwtv5.MapClaims{}
	for k, v := range claims {
		newClaims[k] = v
	}
	now := time.Now()
	newClaims["id"] = username
	newClaims["aud"] = audience
	newClaims["iat"] = now.Unix()
	// Legacy-compatible behavior: very long-lived integration token (100 years).
	newClaims["exp"] = now.Add(100 * 365 * 24 * time.Hour).Unix()

	token := jwtv5.NewWithClaims(jwtv5.SigningMethodHS256, newClaims)
	tokenString, err := token.SignedString([]byte(configuration.Config.Secret_jwt))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to generate token"})
		return
	}

	// Keep exactly one integration token per audience: remove previous ones before adding a new one.
	filtered := make([]string, 0, len(userSession.JWTTokens)+1)
	for _, existing := range userSession.JWTTokens {
		if isIntegrationTokenForAudience(existing, username, audience) {
			continue
		}
		filtered = append(filtered, existing)
	}
	filtered = append(filtered, tokenString)
	userSession.JWTTokens = filtered

	if err := store.SaveSessions(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to persist token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token": tokenString,
	})
}

func checkIntegrationToken(c *gin.Context, audience string) {
	username, userSession, ok := getCurrentSession(c)
	if !ok {
		return
	}

	exists := false
	for _, token := range userSession.JWTTokens {
		if isIntegrationTokenForAudience(token, username, audience) {
			exists = true
			break
		}
	}

	c.JSON(http.StatusOK, gin.H{"exists": exists})
}

func revokeIntegrationTokens(c *gin.Context, audience string) {
	username, userSession, ok := getCurrentSession(c)
	if !ok {
		return
	}

	filtered := make([]string, 0, len(userSession.JWTTokens))

	for _, token := range userSession.JWTTokens {
		if isIntegrationTokenForAudience(token, username, audience) {
			continue
		}
		filtered = append(filtered, token)
	}

	userSession.JWTTokens = filtered
	if err := store.SaveSessions(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to persist token removal"})
		return
	}

	c.Status(http.StatusNoContent)
}

func getCurrentSession(c *gin.Context) (string, *models.UserSession, bool) {
	claims := jwt.ExtractClaims(c)
	username, ok := claims["id"].(string)
	if !ok || username == "" {
		c.JSON(http.StatusBadRequest, gin.H{"message": "invalid user"})
		return "", nil, false
	}

	userSession := store.UserSessions[username]
	if userSession == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "user session not found"})
		return "", nil, false
	}

	return username, userSession, true
}

func isIntegrationTokenForAudience(tokenString string, username string, audience string) bool {
	claims := jwtv5.MapClaims{}
	parser := jwtv5.NewParser(jwtv5.WithoutClaimsValidation())

	_, _, err := parser.ParseUnverified(tokenString, claims)
	if err != nil {
		return false
	}

	id, ok := claims["id"].(string)
	if !ok || id != username {
		return false
	}
	tokenType, ok := claims["aud"].(string)
	if !ok {
		return false
	}
	if tokenType != audience {
		return false
	}
	return true
}

func getAudienceFromRequest(c *gin.Context) (string, bool) {
	audience := strings.TrimSpace(strings.ToLower(c.Param("audience")))
	if audience == "" {
		c.JSON(http.StatusBadRequest, gin.H{"message": "missing audience"})
		return "", false
	}

	if _, ok := allowedIntegrationAudiences[audience]; !ok {
		c.JSON(http.StatusBadRequest, gin.H{"message": "invalid audience"})
		return "", false
	}
	return audience, true
}
