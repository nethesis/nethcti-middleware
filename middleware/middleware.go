/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package middleware

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/fatih/structs"
	"github.com/gin-gonic/gin"

	jwt "github.com/appleboy/gin-jwt/v2"

	"github.com/nethesis/nethcti-middleware/audit"
	"github.com/nethesis/nethcti-middleware/configuration"
	"github.com/nethesis/nethcti-middleware/models"
	"github.com/nethesis/nethcti-middleware/response"
	"github.com/nethesis/nethcti-middleware/utils"
)

type login struct {
	Username string `form:"username" json:"username" binding:"required"`
	Password string `form:"password" json:"password" binding:"required"`
}

type UserSession struct {
	Username    string
	JWTToken    string
	NetCTIToken string
}

var UserSessions = make(map[string]*UserSession)

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
		Key:         []byte(configuration.Config.Secret),
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
				utils.LogError(errors.Wrap(err, "[AUTH] Missing login values"))
				return "", jwt.ErrMissingLoginValues
			}

			// set login credentials
			username := loginVals.Username
			password := loginVals.Password

			// Perform login on the old NetCTI server
			netCtiLoginURL := configuration.Config.V1Protocol + "://" + configuration.Config.V1Endpoint + configuration.Config.V1Path + "/authentication/login"
			payload := map[string]string{"username": username, "password": password}
			payloadBytes, _ := json.Marshal(payload)

			req, err := http.NewRequest("POST", netCtiLoginURL, bytes.NewBuffer(payloadBytes))
			if err != nil {
				utils.LogError(errors.Wrap(err, "[AUTH] Failed to create HTTP request"))
				return nil, err
			}
			req.Header.Set("Content-Type", "application/json")

			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				utils.LogError(errors.Wrap(err, "[AUTH] Failed to send request to NetCTI"))
				return nil, jwt.ErrFailedAuthentication
			}
			defer resp.Body.Close()

			var NetCTIToken string

			if resp.StatusCode == http.StatusUnauthorized {
				wwwAuth := resp.Header.Get("Www-Authenticate")
				if wwwAuth != "" {
					// Generate NetCTIToken using the www-authenticate header
					NetCTIToken = utils.GenerateLegacyToken(resp, username, password)
					if NetCTIToken == "" {
						utils.LogError(errors.New("[AUTH] Failed to generate NetCTIToken"))
						return nil, jwt.ErrFailedAuthentication
					}

					// Retry the request with the new Authorization header
					netCtiMeURL := configuration.Config.V1Protocol + "://" + configuration.Config.V1Endpoint + configuration.Config.V1Path + "/user/me"
					req, _ := http.NewRequest("GET", netCtiMeURL, nil) // Use GET for /user/me
					req.Header.Set("Authorization", NetCTIToken)
					// print request headers
					resp, err = client.Do(req)
					if err != nil {
						utils.LogError(errors.Wrap(err, "[AUTH] Failed to retry request to NetCTI"))
						return nil, jwt.ErrFailedAuthentication
					}
					defer resp.Body.Close()
				}
			}

			if resp.StatusCode != http.StatusOK {
				utils.LogError(errors.Errorf("[AUTH] Authentication failed with status: %d", resp.StatusCode))
				return nil, jwt.ErrFailedAuthentication
			}

			// Login is successful. Middleware returns a JWT.
			// Create a new user session object
			UserSessions[username] = &UserSession{
				Username:    username,
				JWTToken:    "",
				NetCTIToken: NetCTIToken,
			}

			// Store login action
			auditData := models.Audit{
				ID:        0,
				User:      username,
				Action:    "login-ok",
				Data:      "",
				Timestamp: time.Now().UTC(),
			}
			audit.Store(auditData)

			// Return user auth model
			return UserSessions[username], nil
		},
		PayloadFunc: func(data interface{}) jwt.MapClaims {
			// read current user
			if userSession, ok := data.(*UserSession); ok {
				// create claims map
				return jwt.MapClaims{
					identityKey: userSession.Username,
					"role":      "",
					"actions":   []string{},
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
			// Check if the user is logged in
			claims := jwt.ExtractClaims(c)

			username, ok := claims[identityKey].(string)

			userSession := UserSessions[claims[identityKey].(string)]
			JWTToken := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")

			if !ok || UserSessions[username] == nil || JWTToken != userSession.JWTToken {
				return false
			}

			// store auth action
			auditData := models.Audit{
				ID:        0,
				User:      username,
				Action:    "auth-fail",
				Data:      "",
				Timestamp: time.Now().UTC(),
			}
			audit.Store(auditData)

			// not authorized
			return true
		},
		LoginResponse: func(c *gin.Context, code int, token string, t time.Time) {
			// Extract the JWT token from the Authorization header
			tokenObj, _ := InstanceJWT().ParseTokenString(token)
			claims := jwt.ExtractClaimsFromToken(tokenObj)

			// Store the JWT token in the UserSession
			UserSessions[claims[identityKey].(string)].JWTToken = token
			c.JSON(200, gin.H{"code": 200, "expire": t, "token": token})
		},
		LogoutResponse: func(c *gin.Context, code int) {
			// Extract the JWT token from the Authorization header
			JWTToken := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
			tokenObj, _ := InstanceJWT().ParseTokenString(JWTToken)
			claims := jwt.ExtractClaimsFromToken(tokenObj)

			userSession := UserSessions[claims[identityKey].(string)]

			if userSession != nil {
				if JWTToken == userSession.JWTToken {
					delete(UserSessions, claims[identityKey].(string))
				}
			}

			c.JSON(200, gin.H{"code": 200})
		},
		Unauthorized: func(c *gin.Context, code int, message string) {
			if message == "redis is not running" {
				c.JSON(503, structs.Map(response.StatusServiceUnavailable{
					Code:    503,
					Message: message,
					Data:    nil,
				}))
				return
			} else {
				c.JSON(code, structs.Map(response.StatusUnauthorized{
					Code:    code,
					Message: message,
					Data:    nil,
				}))
				return
			}
		},
		TokenLookup:   "header: Authorization, query: jwt",
		TokenHeadName: "Bearer",
		TimeFunc:      time.Now,
	})

	// check middleware errors
	if errDefine != nil {
		utils.LogError(errors.Wrap(errDefine, "[AUTH] middleware definition error"))
	}

	// init middleware
	errInit := authMiddleware.MiddlewareInit()

	// check error on initialization
	if errInit != nil {
		utils.LogError(errors.Wrap(errInit, "[AUTH] middleware initialization error"))
	}

	// return object
	return authMiddleware
}
