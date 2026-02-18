/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package methods

import (
	"net/http"
	"time"

	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"
	jwtv4 "github.com/golang-jwt/jwt/v4"

	"github.com/nethesis/nethcti-middleware/configuration"
	"github.com/nethesis/nethcti-middleware/models"
	"github.com/nethesis/nethcti-middleware/store"
)

const (
	integrationPhoneIsland = "phone-island"
	integrationApp         = "mobile-app"
)

// CreatePhoneIslandToken creates a JWT integration token for Phone Island.
func CreatePhoneIslandToken(c *gin.Context) {
	issueIntegrationToken(c, integrationPhoneIsland)
}

// CreateQRCodeToken creates a JWT integration token for QRCode login.
func CreateQRCodeToken(c *gin.Context) {
	issueIntegrationToken(c, integrationApp)
}

// CheckPhoneIslandToken checks if at least one valid Phone Island integration token exists.
func CheckPhoneIslandToken(c *gin.Context) {
	checkIntegrationToken(c, integrationPhoneIsland)
}

// RemovePhoneIslandToken revokes all Phone Island integration JWTs for the authenticated user.
func RemovePhoneIslandToken(c *gin.Context) {
	revokeIntegrationTokens(c, integrationPhoneIsland)
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

	newClaims := jwtv4.MapClaims{}
	for k, v := range claims {
		newClaims[k] = v
	}
	newClaims["id"] = username
	newClaims["aud"] = audience
	// Legacy-compatible behavior: very long-lived integration token (100 years).
	newClaims["exp"] = time.Now().Add(100 * 365 * 24 * time.Hour).Unix()

	token := jwtv4.NewWithClaims(jwtv4.SigningMethodHS256, newClaims)
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
		"token":    tokenString,
		"username": username,
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
	removed := 0

	for _, token := range userSession.JWTTokens {
		if isIntegrationTokenForAudience(token, username, audience) {
			removed++
			continue
		}
		filtered = append(filtered, token)
	}

	userSession.JWTTokens = filtered
	if err := store.SaveSessions(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to persist token removal"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"removed": removed > 0, "count": removed})
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
	claims := jwtv4.MapClaims{}
	parser := jwtv4.NewParser(jwtv4.WithoutClaimsValidation())

	_, _, err := parser.ParseUnverified(tokenString, claims)
	if err != nil {
		return false
	}

	id, ok := claims["id"].(string)
	if !ok || id != username {
		return false
	}
	tokenType, ok := claims["aud"].(string)
	if !ok || tokenType != audience {
		return false
	}
	return true
}
