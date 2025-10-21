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

	jwtv4 "github.com/golang-jwt/jwt/v4"

	"github.com/nethesis/nethcti-middleware/configuration"
	"github.com/nethesis/nethcti-middleware/logs"
	"github.com/nethesis/nethcti-middleware/store"
	"github.com/nethesis/nethcti-middleware/utils"
)

func DeleteExpiredTokens() {
	// iterate through all user sessions
	for username, userSession := range store.UserSessions {
		// parse JWT token to check expiration
		for _, tokenRaw := range userSession.JWTTokens {

			token, err := jwtv4.Parse(tokenRaw, func(token *jwtv4.Token) (interface{}, error) {
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
	}

	logs.Log("[INFO][JWT] Completed cleanup of expired user sessions")
}

// VerifyUserPassword verifies a user's password against NetCTI server
func VerifyUserPassword(username, password string) bool {
	// verify password against NetCTI server
	netCtiLoginURL := configuration.Config.V1Protocol + "://" + configuration.Config.V1ApiEndpoint + configuration.Config.V1ApiPath + "/authentication/login"
	payload := map[string]string{"username": username, "password": password}
	payloadBytes, _ := json.Marshal(payload)

	req, err := http.NewRequest("POST", netCtiLoginURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		logs.Log("[AUTH] Failed to create HTTP request for password verification")
		return false
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		logs.Log("[AUTH] Failed to send password verification request to NetCTI")
		return false
	}
	defer resp.Body.Close()

	var NethCTIToken string
	isValidPassword := false

	switch resp.StatusCode {
	case http.StatusUnauthorized:
		wwwAuth := resp.Header.Get("Www-Authenticate")
		if wwwAuth != "" {
			// Generate NethCTIToken using the www-authenticate header
			NethCTIToken = utils.GenerateLegacyToken(resp, username, password)
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

	return isValidPassword
}
