/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package main

import (
	"io"

	"github.com/gin-contrib/cors"
	"github.com/gin-contrib/gzip"
	"github.com/gin-gonic/gin"
	"github.com/robfig/cron/v3"

	"github.com/nethesis/nethcti-middleware/configuration"
	"github.com/nethesis/nethcti-middleware/logs"
	"github.com/nethesis/nethcti-middleware/methods"
	"github.com/nethesis/nethcti-middleware/middleware"
	"github.com/nethesis/nethcti-middleware/socket"
	"github.com/nethesis/nethcti-middleware/store"
)

func main() {
	// Init logger
	logs.Init("nethcti-middleware")

	// Init configuration
	configuration.Init()

	// Init store
	store.UserSessionInit()

	// Create router
	router := createRouter()

	// Create cron to run daily
	c := cron.New()
	c.AddFunc("@daily", methods.DeleteExpiredTokens)
	c.Start()

	// Run server
	router.Run(configuration.Config.ListenAddress)
}

func createRouter() *gin.Engine {
	// Disable log to stdout when running in release mode
	if gin.Mode() == gin.ReleaseMode {
		gin.DefaultWriter = io.Discard
	}

	// Init routers
	router := gin.New()
	router.RedirectTrailingSlash = false
	router.Use(
		gin.LoggerWithWriter(gin.DefaultWriter),
		gin.Recovery(),
	)

	// Add default compression
	router.Use(gzip.Gzip(gzip.DefaultCompression))

	// Cors configuration only in debug mode GIN_MODE=debug
	if gin.Mode() == gin.DebugMode {
		// gin gonic cors conf
		corsConf := cors.DefaultConfig()
		corsConf.AllowHeaders = []string{"Authorization", "Content-Type", "Accept"}
		corsConf.AllowAllOrigins = true
		router.Use(cors.New(corsConf))
	}

	// Define api group
	api := router.Group("")

	// Define public endpoints
	api.POST("/login", middleware.InstanceJWT().LoginHandler)
	api.GET("/ws/", socket.WsProxyHandler)

	// Authentication required endpoints
	api.Use(middleware.InstanceJWT().MiddlewareFunc())
	{
		// 2FA APIs
		api.POST("/2fa/disable", methods.Disable2FA)
		api.POST("/2fa/verify-otp", methods.VerifyOTP)
		api.GET("/2fa/status", methods.Get2FAStatus)
		api.POST("/2fa/recovery-codes", methods.Get2FARecoveryCodes)
		api.GET("/2fa/qr-code", methods.QRCode)

		// Phone Island Integration APIs
		api.POST("/authentication/phone_island_token_login", methods.PhoneIslandTokenLogin)
		api.POST("/authentication/persistent_token_remove", methods.PhoneIslandTokenRemove)
		api.GET("/authentication/phone_island_token_check", methods.PhoneIslandTokenCheck)

		// Logout endpoint
		api.POST("/logout", middleware.InstanceJWT().LogoutHandler)
	}

	// Handle missing endpoint
	router.NoRoute(func(c *gin.Context) {
		path := c.Request.URL.Path

		// Check if this is a FreePBX admin transparent API call
		userHeader := c.GetHeader("User")
		secretKeyHeader := c.GetHeader("Secretkey")
		isFreePBXAdmin := userHeader == "admin" && secretKeyHeader != ""

		// Check if the API is in the FreePBX API list (exact match)
		isFreePBXAPI := false
		for _, freepbxPath := range configuration.Config.FreePBXAPIs {
			if path == freepbxPath {
				isFreePBXAPI = true
				break
			}
		}

		if isFreePBXAdmin && isFreePBXAPI {
			// Handle FreePBX API call - add authorization_user header and forward directly
			c.Request.Header.Set("Authorization-User", "admin")
			methods.ProxyV1Request(c, path)
		} else {
			// Apply JWT middleware for regular APIs
			middleware.InstanceJWT().MiddlewareFunc()(c)
			if c.IsAborted() {
				return
			}
			// Fallback to proxy logic for legacy V1 API
			methods.ProxyV1Request(c, path)
		}
	})

	return router
}
