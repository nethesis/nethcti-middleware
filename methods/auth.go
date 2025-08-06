/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package methods

import (
	"bytes"
	"encoding/json"
	"net/http"
	"time"

	"github.com/fatih/structs"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	jwtv4 "github.com/golang-jwt/jwt/v4"

	"github.com/nethesis/nethcti-middleware/configuration"
	"github.com/nethesis/nethcti-middleware/logs"
	"github.com/nethesis/nethcti-middleware/models"
	"github.com/nethesis/nethcti-middleware/store"
	"github.com/nethesis/nethcti-middleware/utils"
)

func DeleteExpiredTokens() {
	// iterate through all user sessions
	for username, userSession := range store.UserSessions {
		// parse JWT token to check expiration
		token, err := jwtv4.Parse(userSession.JWTToken, func(token *jwtv4.Token) (interface{}, error) {
			return []byte(configuration.Config.Secret_jwt), nil
		})

		// check if token is valid and not expired
		isValid := false
		if err == nil && token.Valid {
			if claims, ok := token.Claims.(jwtv4.MapClaims); ok {
				if exp, ok := claims["exp"].(float64); ok {
					// check if token is not expired
					if time.Now().Unix() < int64(exp) {
						isValid = true
					}
				}
			}
		}

		// remove session if token is expired or invalid
		if !isValid {
			delete(store.UserSessions, username)
			logs.Log("[INFO][JWT] Removed expired session for user: " + username)
		}
	}

	logs.Log("[INFO][JWT] Completed cleanup of expired user sessions")
}

func VerifyPassword(c *gin.Context) {
	// get payload
	var loginData models.LoginJson

	if err := c.ShouldBindBodyWith(&loginData, binding.JSON); err != nil {
		c.JSON(http.StatusBadRequest, structs.Map(models.StatusBadRequest{
			Code:    400,
			Message: "request fields malformed",
			Data:    err.Error(),
		}))
		return
	}

	// validate required fields
	if loginData.Username == "" || loginData.Password == "" {
		c.JSON(http.StatusBadRequest, structs.Map(models.StatusBadRequest{
			Code:    400,
			Message: "username and password are required",
			Data:    "",
		}))
		return
	}

	// verify password against NetCTI server
	netCtiLoginURL := configuration.Config.V1Protocol + "://" + configuration.Config.V1ApiEndpoint + configuration.Config.V1ApiPath + "/authentication/login"
	payload := map[string]string{"username": loginData.Username, "password": loginData.Password}
	payloadBytes, _ := json.Marshal(payload)

	req, err := http.NewRequest("POST", netCtiLoginURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		logs.Log("[AUTH] Failed to create HTTP request for password verification")
		c.JSON(http.StatusInternalServerError, structs.Map(models.StatusInternalServerError{
			Code:    500,
			Message: "failed to create verification request",
			Data:    "",
		}))
		return
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		logs.Log("[AUTH] Failed to send password verification request to NetCTI")
		c.JSON(http.StatusInternalServerError, structs.Map(models.StatusInternalServerError{
			Code:    500,
			Message: "failed to contact authentication server",
			Data:    "",
		}))
		return
	}
	defer resp.Body.Close()

	var NethCTIToken string
	isValidPassword := false

	switch resp.StatusCode {
	case http.StatusUnauthorized:
		wwwAuth := resp.Header.Get("Www-Authenticate")
		if wwwAuth != "" {
			// Generate NethCTIToken using the www-authenticate header
			NethCTIToken = utils.GenerateLegacyToken(resp, loginData.Username, loginData.Password)
			if NethCTIToken != "" {
				// Verify the generated token by making a request to /user/me
				netCtiMeURL := configuration.Config.V1Protocol + "://" + configuration.Config.V1ApiEndpoint + configuration.Config.V1ApiPath + "/user/me"
				req, _ := http.NewRequest("GET", netCtiMeURL, nil)
				req.Header.Set("Authorization", NethCTIToken)

				resp, err = client.Do(req)
				if err == nil && resp.StatusCode == http.StatusOK {
					isValidPassword = true
				}
				if resp != nil {
					resp.Body.Close()
				}
			}
		}
	case http.StatusOK:
		isValidPassword = true
	}

	if isValidPassword {
		c.JSON(http.StatusOK, structs.Map(models.StatusOK{
			Code:    200,
			Message: "password verified successfully",
			Data:    gin.H{"valid": true},
		}))
	} else {
		c.JSON(http.StatusUnauthorized, structs.Map(models.StatusUnauthorized{
			Code:    401,
			Message: "invalid credentials",
			Data:    gin.H{"valid": false},
		}))
	}
}
