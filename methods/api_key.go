/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package methods

import (
	"encoding/json"
	"net/http"
	"os"
	"time"

	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"
	jwtv4 "github.com/golang-jwt/jwt/v4"
	"github.com/nethesis/nethcti-middleware/configuration"
	"github.com/nethesis/nethcti-middleware/models"
	"github.com/nethesis/nethcti-middleware/store"
)

// -------------------------------- exported methods --------------------------------

// PhoneIslandTokenLogin handles the login for Phone Island using a JWT token
func PhoneIslandTokenLogin(c *gin.Context) {
	claims := jwt.ExtractClaims(c)
	username, ok := claims["id"].(string)
	if !ok || username == "" {
		c.JSON(http.StatusBadRequest, gin.H{"message": "invalid user"})
		return
	}

	// Get token from CTI Server
	userSession := store.UserSessions[username]
	nethctiToken := userSession.NethCTIToken

	req, err := http.NewRequest("POST", configuration.Config.V1Protocol+"://"+configuration.Config.V1ApiEndpoint+configuration.Config.V1ApiPath+"/authentication/phone_island_token_login", nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to create request"})
		return
	}
	req.Header.Set("Authorization", nethctiToken)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to contact server v1"})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		c.JSON(http.StatusBadGateway, gin.H{"message": "server v1 returned error", "status": resp.StatusCode})
		return
	}

	var v1Resp struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&v1Resp); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to parse server v1 response"})
		return
	}

	phoneIslandToken := v1Resp.Token

	apiKey, err := generateAPIKey(username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to generate api key"})
		return
	}
	if err := saveAPIKey(username, apiKey, phoneIslandToken); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to save api key"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token":    apiKey,
		"username": username,
	})
}

// PhoneIslandTokenRemove removes the Phone Island API key for the user
func PhoneIslandTokenRemove(c *gin.Context) {
	claims := jwt.ExtractClaims(c)
	username, ok := claims["id"].(string)
	if !ok || username == "" {
		c.JSON(http.StatusBadRequest, gin.H{"message": "invalid user"})
		return
	}

	err := os.Remove(configuration.Config.SecretsDir + "/" + username + "/phone_island_api_key.json")
	if err != nil {
		if os.IsNotExist(err) {
			c.JSON(http.StatusOK, gin.H{"removed": false, "message": "api key not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"removed": false, "message": "failed to remove api key"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"removed": true})
}

// PhoneIslandTokenCheck checks if the user has a Phone Island API key
func PhoneIslandTokenCheck(c *gin.Context) {
	claims := jwt.ExtractClaims(c)
	username, ok := claims["id"].(string)
	if !ok || username == "" {
		c.JSON(http.StatusBadRequest, gin.H{"message": "invalid user"})
		return
	}

	exists := false
	if _, err := os.Stat(configuration.Config.SecretsDir + "/" + username + "/phone_island_api_key.json"); err == nil {
		exists = true
	} else if !os.IsNotExist(err) {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to check api key"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"exists": exists})
}

// AuthenticateAPIKey returns true if the API key matches the stored key for the user, false otherwise
func AuthenticateAPIKey(username, apiKey string) bool {
	dir := configuration.Config.SecretsDir + "/" + username
	filePath := dir + "/phone_island_api_key.json"

	// Check if directory exists
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return false
	}

	// Check if file exists
	data, err := os.ReadFile(filePath)
	if err != nil {
		return false
	}

	// Unmarshal the JSON data
	var keyData models.ApiKeyData
	if err := json.Unmarshal(data, &keyData); err != nil {
		return false
	}

	return keyData.APIKey == apiKey
}

// Return the PhoneIslandToken from ApiKeyData given a JWT token string
func GetPhoneIslandToken(jwtToken string, onlyToken bool) (string, error) {
	// Parse the JWT token to extract the username (id)
	token, err := jwtv4.Parse(jwtToken, func(token *jwtv4.Token) (interface{}, error) {
		return []byte(configuration.Config.Secret_jwt), nil
	})
	if err != nil || !token.Valid {
		return "", err
	}

	claims, ok := token.Claims.(jwtv4.MapClaims)
	if !ok {
		return "", err
	}

	username, ok := claims["id"].(string)
	if !ok || username == "" {
		return "", err
	}

	dir := configuration.Config.SecretsDir + "/" + username
	filePath := dir + "/phone_island_api_key.json"

	// Check if file exists
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", err
	}

	var keyData models.ApiKeyData
	if err := json.Unmarshal(data, &keyData); err != nil {
		return "", err
	}

	if onlyToken {
		return keyData.PhoneIslandToken, nil
	} else {
		completedToken := keyData.Username + ":" + keyData.PhoneIslandToken
		return completedToken, nil
	}
}

// -------------------------------- private methods --------------------------------

// generateAPIKey generates a JWT token for the user with a long expiration time
func generateAPIKey(username string) (string, error) {
	claims := jwtv4.MapClaims{
		"id":  username,
		"2fa": false,
		"exp": time.Now().Add(100 * 365 * 24 * time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}

	token := jwtv4.NewWithClaims(jwtv4.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(configuration.Config.Secret_jwt))
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

// saveAPIKey saves the API key and Phone Island token to a file for the user
func saveAPIKey(username string, apiKey string, phoneIslandToken string) error {
	dir := configuration.Config.SecretsDir + "/" + username
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}

	data := models.ApiKeyData{
		Username:         username,
		APIKey:           apiKey,
		PhoneIslandToken: phoneIslandToken,
	}

	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return err
	}

	f, err := os.OpenFile(dir+"/phone_island_api_key.json", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Write(jsonBytes)
	if err != nil {
		return err
	}

	return nil
}
