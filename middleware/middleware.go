/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package middleware

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/fatih/structs"
	"github.com/gin-gonic/gin"
	"github.com/nqd/flat"

	jwt "github.com/appleboy/gin-jwt/v2"

	"github.com/nethesis/nethcti-middleware/configuration"
	"github.com/nethesis/nethcti-middleware/logs"
	"github.com/nethesis/nethcti-middleware/methods"
	"github.com/nethesis/nethcti-middleware/models"
	"github.com/nethesis/nethcti-middleware/store"
	"github.com/nethesis/nethcti-middleware/utils"
)

type login struct {
	Username string `form:"username" json:"username" binding:"required"`
	Password string `form:"password" json:"password" binding:"required"`
}

var jwtMiddleware *jwt.GinJWTMiddleware
var identityKey = "id"

func InstanceJWT() *jwt.GinJWTMiddleware {
	if jwtMiddleware == nil {
		jwtMiddleware = InitJWT()
	}
	return jwtMiddleware
}

func InitJWT() *jwt.GinJWTMiddleware {
	// define jwt middleware
	authMiddleware, errDefine := jwt.New(&jwt.GinJWTMiddleware{
		Realm:       "nethcti",
		Key:         []byte(configuration.Config.Secret_jwt),
		Timeout:     time.Hour * 24 * 14, // 2 weeks
		IdentityKey: identityKey,
		Authenticator: func(c *gin.Context) (interface{}, error) {
			// Ensure jwtMiddleware is initialized before using it
			if jwtMiddleware == nil {
				jwtMiddleware = InitJWT()
			}

			// check login credentials exists
			var loginVals login
			if err := c.ShouldBind(&loginVals); err != nil {
				logs.Log("[AUTH] Missing login values")
				return "", jwt.ErrMissingLoginValues
			}

			// set login credentials
			username := loginVals.Username
			password := loginVals.Password

			// Perform login on the old NetCTI server
			netCtiLoginURL := configuration.Config.V1Protocol + "://" + configuration.Config.V1ApiEndpoint + configuration.Config.V1ApiPath + "/authentication/login"
			payload := map[string]string{"username": username, "password": password}
			payloadBytes, _ := json.Marshal(payload)

			req, err := http.NewRequest("POST", netCtiLoginURL, bytes.NewBuffer(payloadBytes))
			if err != nil {
				logs.Log("[AUTH] Failed to create HTTP request")
				return nil, err
			}
			req.Header.Set("Content-Type", "application/json")

			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				logs.Log("[AUTH] Failed to send request to NetCTI")
				return nil, jwt.ErrFailedAuthentication
			}
			defer resp.Body.Close()

			var NethCTIToken string

			if resp.StatusCode == http.StatusUnauthorized {
				wwwAuth := resp.Header.Get("Www-Authenticate")
				if wwwAuth != "" {
					// Generate NethCTIToken using the www-authenticate header
					NethCTIToken = utils.GenerateLegacyToken(resp, username, password)
					if NethCTIToken == "" {
						logs.Log("[AUTH] Failed to generate NethCTIToken")
						return nil, jwt.ErrFailedAuthentication
					}

					// Retry the request with the new Authorization header
					netCtiMeURL := configuration.Config.V1Protocol + "://" + configuration.Config.V1ApiEndpoint + configuration.Config.V1ApiPath + "/user/me"
					req, _ := http.NewRequest("GET", netCtiMeURL, nil) // Use GET for /user/me
					req.Header.Set("Authorization", NethCTIToken)
					// print request headers
					resp, err = client.Do(req)
					if err != nil {
						logs.Log("[AUTH] Failed to retry request to NetCTI")
						return nil, jwt.ErrFailedAuthentication
					}
					defer resp.Body.Close()
				}
			}

			if resp.StatusCode != http.StatusOK {
				logs.Log("[ERROR][AUTH] Authentication failed for user " + username + " with status: " + resp.Status)
				return nil, jwt.ErrFailedAuthentication
			}

			// Login is successful. Middleware returns a JWT.
			// Check if user session already exists (multi-session support)
			existingSession, sessionExists := store.UserSessions[username]

			if sessionExists {
				// Reuse existing session (keep existing tokens, update NethCTIToken)
				// Note: New login does NOT inherit OTP_Verified status - each JWT token will be verified independently
				existingSession.NethCTIToken = NethCTIToken
				logs.Log("[INFO][AUTH] authentication success for user " + username + " (reusing existing session with " + fmt.Sprint(len(existingSession.JWTTokens)) + " existing tokens)")
				return existingSession, nil
			} else {
				// Create a new user session object
				store.UserSessions[username] = &models.UserSession{
					Username:     username,
					JWTTokens:    nil,
					NethCTIToken: NethCTIToken,
					OTP_Verified: false,
				}
				logs.Log("[INFO][AUTH] authentication success for user " + username + " (new session created)")
				return store.UserSessions[username], nil
			}
		},
		PayloadFunc: func(data interface{}) jwt.MapClaims {
			// read current user
			if userSession, ok := data.(*models.UserSession); ok {
				// check if user require 2fa
				status, _ := methods.GetUserStatus(userSession.Username)

				// create claims map
				// Note: otp_verified is always false on initial login
				// It will be set to true only after OTP verification via regenerateUserToken
				return jwt.MapClaims{
					identityKey:    userSession.Username,
					"2fa":          status == "1",
					"otp_verified": false,
				}
			}

			// return claims map
			return jwt.MapClaims{}
		},
		IdentityHandler: func(c *gin.Context) interface{} {
			// handle identity and extract claims
			claims := jwt.ExtractClaims(c)

			username := claims[identityKey].(string)

			// return username
			return username
		},
		Authorizator: func(data interface{}, c *gin.Context) bool {
			// Extract claims and session info
			claims := jwt.ExtractClaims(c)
			username := claims[identityKey].(string)

			reqMethod := c.Request.Method
			reqURI := c.Request.RequestURI
			JWTToken := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
			userSession := store.UserSessions[username]

			// Check if session exists and token is valid
			if userSession == nil || !utils.Contains(JWTToken, userSession.JWTTokens) {
				// Try API key authentication as fallback
				if !methods.AuthenticateAPIKey(username, JWTToken) {
					logs.Log("[ERROR][AUTH] authorization failed for user " + username + " (session not found or invalid token). " + reqMethod + " " + reqURI)
					return false
				}
				// API key auth succeeded, skip 2FA checks
				logs.Log("[INFO][AUTH] API key authentication success for user " + username)
				return true
			}

			isOTPVerifyEndpoint := strings.Contains(c.Request.RequestURI, "/verify-otp")

			// Check 2FA requirement (only for JWT token authentication, not API key)
			// Use the otp_verified claim from the JWT token (not from session)
			if !isOTPVerifyEndpoint {
				has2FA, has2FAExists := claims["2fa"].(bool)
				otpVerified, otpVerifiedExists := claims["otp_verified"].(bool)

				// If 2FA is enabled but OTP claim doesn't exist or is false, deny access
				if has2FAExists && has2FA && (!otpVerifiedExists || !otpVerified) {
					logs.Log("[ERROR][AUTH] authorization failed for user " + username + " (2FA required but OTP not verified in token). " + reqMethod + " " + reqURI)
					return false
				}
			}

			reqBody := ""
			if reqMethod == "POST" || reqMethod == "PUT" {
				// extract body
				var buf bytes.Buffer
				tee := io.TeeReader(c.Request.Body, &buf)
				body, _ := io.ReadAll(tee)
				c.Request.Body = io.NopCloser(&buf)

				// convert to map and flat it
				var jsonDyn map[string]interface{}
				json.Unmarshal(body, &jsonDyn)
				in, _ := flat.Flatten(jsonDyn, nil)

				// search for sensitve data, in sensitive list
				for k := range in {
					for _, s := range configuration.Config.SensitiveList {
						if strings.Contains(strings.ToLower(k), strings.ToLower(s)) {
							in[k] = "XXX"
						}
					}
				}

				// unflat the map
				out, _ := flat.Unflatten(in, nil)

				// convert to json string
				jsonOut, _ := json.Marshal(out)

				// compose string
				reqBody = string(jsonOut)
			}

			logs.Log("[INFO][AUTH] authorization success for user " + claims["id"].(string) + ". " + reqMethod + " " + reqURI + " " + reqBody)

			return true
		},
		LoginResponse: func(c *gin.Context, code int, token string, t time.Time) {
			// Extract the JWT token from the Authorization header
			tokenObj, _ := InstanceJWT().ParseTokenString(token)
			claims := jwt.ExtractClaimsFromToken(tokenObj)

			// Store the JWT token in the UserSession
			store.UserSessions[claims[identityKey].(string)].JWTTokens = append(store.UserSessions[claims[identityKey].(string)].JWTTokens, token)
			c.JSON(200, gin.H{"code": 200, "expire": t, "token": token})
		},
		LogoutResponse: func(c *gin.Context, code int) {
			// Extract the JWT token from the Authorization header
			JWTToken := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
			tokenObj, _ := InstanceJWT().ParseTokenString(JWTToken)
			claims := jwt.ExtractClaimsFromToken(tokenObj)
			username := claims[identityKey].(string)

			userSession := store.UserSessions[username]

			if userSession != nil {
				// Remove only this specific token from the user's token array
				if utils.Contains(JWTToken, userSession.JWTTokens) {
					userSession.JWTTokens = utils.Remove(JWTToken, userSession.JWTTokens)
					logs.Log("[INFO][AUTH] Logged out token for user " + username)

					// If no more tokens, delete the entire session
					if len(userSession.JWTTokens) == 0 {
						delete(store.UserSessions, username)
						logs.Log("[INFO][AUTH] Deleted session for user " + username + " (no more active tokens)")
					}
				}
			}

			c.JSON(200, gin.H{"code": 200})
		},
		Unauthorized: func(c *gin.Context, code int, message string) {
			c.JSON(code, structs.Map(models.StatusUnauthorized{
				Code:    code,
				Message: message,
				Data:    nil,
			}))
		},
		TokenLookup:   "header: Authorization, query: jwt",
		TokenHeadName: "Bearer",
		TimeFunc:      time.Now,
	})

	// check middleware errors
	if errDefine != nil {
		logs.Log("[AUTH] middleware definition error")
	}

	// init middleware
	errInit := authMiddleware.MiddlewareInit()

	// check error on initialization
	if errInit != nil {
		logs.Log("[AUTH] middleware initialization error")
	}

	// return object
	return authMiddleware
}
