/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package methods

import (
	"bytes"
	"encoding/json"
	"errors"
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

const phoneIslandWebSubtype = "web"
const phoneIslandNethlinkSubtype = "nethlink"
const mobileQRSubtype = "mobileqr"

const mobileQRAPIKeyFilename = "mobile_qr_api_key.json"

// -------------------------------- exported methods --------------------------------

// PhoneIslandTokenLogin handles the login for Phone Island using a JWT token
func PhoneIslandTokenLogin(c *gin.Context) {
	claims := jwt.ExtractClaims(c)
	username, ok := claims["id"].(string)
	if !ok || username == "" {
		c.JSON(http.StatusBadRequest, gin.H{"message": "invalid user"})
		return
	}

	// Read subtype from request body
	var requestBody struct {
		Subtype string `json:"subtype"`
	}
	if err := c.ShouldBindJSON(&requestBody); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "invalid request body"})
		return
	}

	subtype := requestBody.Subtype
	if subtype == "" {
		subtype = phoneIslandWebSubtype
	}

	// Check if a phone_island_token already exists for any other subtype
	// If it does, reuse it to avoid invalidating existing sessions
	var phoneIslandToken string
	existingToken, err := getExistingPhoneIslandToken(username)
	if err == nil && existingToken != "" {
		// Reuse existing token from another subtype
		phoneIslandToken = existingToken
	} else {
		// Get new token from CTI Server
		userSession := store.UserSessions[username]
		nethctiToken := userSession.NethCTIToken

		phoneIslandPayload := map[string]string{"subtype": subtype}
		phoneIslandPayloadBytes, _ := json.Marshal(phoneIslandPayload)
		req, err := http.NewRequest("POST", configuration.Config.V1Protocol+"://"+configuration.Config.V1ApiEndpoint+configuration.Config.V1ApiPath+"/authentication/phone_island_token_login", bytes.NewBuffer(phoneIslandPayloadBytes))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to create request"})
			return
		}
		req.Header.Set("Authorization", nethctiToken)
		req.Header.Set("Content-Type", "application/json")

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

		phoneIslandToken = v1Resp.Token
	}

	apiKey, err := generateAPIKey(username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to generate api key"})
		return
	}
	if err := saveAPIKey(username, apiKey, phoneIslandToken, subtype); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to save api key"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token":    apiKey,
		"username": username,
	})
}

// MobileQRCodeTokenLogin generates a dedicated API key JWT for mobile QR login.
// The returned JWT is independent from the current web session JWT.
func MobileQRCodeTokenLogin(c *gin.Context) {
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

	legacyURL := configuration.Config.V1Protocol + "://" + configuration.Config.V1ApiEndpoint + configuration.Config.V1ApiPath + "/authentication/persistent_token_login"
	req, err := http.NewRequest("POST", legacyURL, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to create request"})
		return
	}
	req.Header.Set("Authorization", userSession.NethCTIToken)

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
	if v1Resp.Token == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "empty token from server v1"})
		return
	}

	apiKey, err := generateAPIKey(username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to generate api key"})
		return
	}
	if err := saveMobileQRCodeAPIKey(username, apiKey, v1Resp.Token); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to save mobile qr api key"})
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

	// Read subtype from request body
	var requestBody struct {
		Subtype string `json:"subtype"`
	}
	if err := c.ShouldBindJSON(&requestBody); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "invalid request body"})
		return
	}

	subtype := requestBody.Subtype
	if subtype == "" {
		subtype = phoneIslandWebSubtype
	}

	// Call legacy endpoint to remove persistent token (Phone Island session invalidation)
	userSession, ok := store.UserSessions[username]
	if !ok || userSession.NethCTIToken == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "user session not found"})
		return
	}

	legacyURL := configuration.Config.V1Protocol + "://" + configuration.Config.V1ApiEndpoint + configuration.Config.V1ApiPath + "/authentication/persistent_token_remove"
	removePayload := struct {
		Type    string `json:"type"`
		Subtype string `json:"subtype"`
	}{Type: "phone-island", Subtype: subtype}
	removePayloadBytes, _ := json.Marshal(removePayload)
	req, err := http.NewRequest("POST", legacyURL, bytes.NewBuffer(removePayloadBytes))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to create legacy remove request"})
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", userSession.NethCTIToken)

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

	dir := configuration.Config.SecretsDir + "/" + username
	removed := false
	subtypes := []string{phoneIslandWebSubtype, phoneIslandNethlinkSubtype}

	for _, subtype := range subtypes {
		filePath := dir + "/phone_island_api_key_" + subtype + ".json"
		err := os.Remove(filePath)
		if err == nil {
			removed = true
		}
	}

	if !removed {
		c.JSON(http.StatusOK, gin.H{"removed": false, "message": "api key not found"})
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

	// First call legacy endpoint to check remote existence
	remoteExists := false
	userSession, ok := store.UserSessions[username]
	if ok && userSession.NethCTIToken != "" { // only attempt if we have a session
		legacyURL := configuration.Config.V1Protocol + "://" + configuration.Config.V1ApiEndpoint + configuration.Config.V1ApiPath + "/phone_island_token_check/web"
		req, err := http.NewRequest("GET", legacyURL, nil)
		if err == nil {
			req.Header.Set("Authorization", userSession.NethCTIToken)
			client := &http.Client{Timeout: 10 * time.Second}
			resp, err := client.Do(req)
			if err == nil {
				defer resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					var legacyResp struct {
						Exists bool `json:"exists"`
					}
					if err := json.NewDecoder(resp.Body).Decode(&legacyResp); err == nil {
						remoteExists = legacyResp.Exists
					}
				}
			}
		}
	}

	// Local file-based check (previous behavior)
	dir := configuration.Config.SecretsDir + "/" + username
	localExists := false
	subtypes := []string{phoneIslandWebSubtype, phoneIslandNethlinkSubtype}
	for _, subtype := range subtypes {
		filePath := dir + "/phone_island_api_key_" + subtype + ".json"
		if _, err := os.Stat(filePath); err == nil {
			localExists = true
			break
		} else if !os.IsNotExist(err) {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to check api key"})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"exists": remoteExists && localExists})
}

// AuthenticateAPIKey returns true if the API key matches the stored key for the user, false otherwise
func AuthenticateAPIKey(username, apiKey string) bool {
	for _, filePath := range apiKeyFilePaths(username) {
		keyData, err := readAPIKeyData(filePath)
		if err == nil && keyData.APIKey == apiKey {
			return true
		}
	}

	return false
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

	for _, filePath := range apiKeyFilePaths(username) {
		keyData, err := readAPIKeyData(filePath)
		if err != nil {
			continue
		}
		// Check if this API key matches the JWT token
		if keyData.APIKey == jwtToken {
			if onlyToken {
				return keyData.PhoneIslandToken, nil
			} else {
				completedToken := keyData.Username + ":" + keyData.PhoneIslandToken
				return completedToken, nil
			}
		}
	}

	return "", os.ErrNotExist
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

// getExistingPhoneIslandToken checks if a phone_island_token already exists for the user
// in any subtype file and returns it. This prevents invalidating existing sessions.
func getExistingPhoneIslandToken(username string) (string, error) {
	dir := configuration.Config.SecretsDir + "/" + username
	subtypes := []string{phoneIslandWebSubtype, phoneIslandNethlinkSubtype}

	for _, subtype := range subtypes {
		filePath := dir + "/phone_island_api_key_" + subtype + ".json"

		data, err := os.ReadFile(filePath)
		if err != nil {
			continue
		}

		var keyData models.ApiKeyData
		if err := json.Unmarshal(data, &keyData); err != nil {
			continue
		}

		// Return the first valid phone_island_token we find
		if keyData.PhoneIslandToken != "" {
			return keyData.PhoneIslandToken, nil
		}
	}

	return "", os.ErrNotExist
}

// saveAPIKey saves the API key and Phone Island token to a file for the user
func saveAPIKey(username string, apiKey string, phoneIslandToken string, subtype string) error {
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
		Subtype:          subtype,
	}

	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return err
	}

	filename := dir + "/phone_island_api_key_" + subtype + ".json"
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
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

func saveMobileQRCodeAPIKey(username string, apiKey string, persistentToken string) error {
	dir := configuration.Config.SecretsDir + "/" + username
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}

	data := models.ApiKeyData{
		Username:         username,
		APIKey:           apiKey,
		PhoneIslandToken: persistentToken,
		Subtype:          mobileQRSubtype,
	}

	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return err
	}

	filename := dir + "/" + mobileQRAPIKeyFilename
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Write(jsonBytes)
	return err
}

func apiKeyFilePaths(username string) []string {
	dir := configuration.Config.SecretsDir + "/" + username
	return []string{
		dir + "/phone_island_api_key_" + phoneIslandWebSubtype + ".json",
		dir + "/phone_island_api_key_" + phoneIslandNethlinkSubtype + ".json",
		dir + "/" + mobileQRAPIKeyFilename,
	}
}

func readAPIKeyData(filePath string) (*models.ApiKeyData, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var keyData models.ApiKeyData
	if err := json.Unmarshal(data, &keyData); err != nil {
		return nil, err
	}
	if keyData.APIKey == "" {
		return nil, errors.New("empty api key")
	}

	return &keyData, nil
}
