/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package main

import (
	"io"
	"net/http"

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
	// init logger
	logs.Init("nethcti-middleware")

	// init configuration
	configuration.Init()

	// init store
	store.UserSessionInit()

	// create router
	router := createRouter()

	// create cron to run daily
	c := cron.New()
	c.AddFunc("@daily", methods.DeleteExpiredTokens)
	c.Start()

	// run server
	router.Run(configuration.Config.ListenAddress)
}

func createRouter() *gin.Engine {
	// disable log to stdout when running in release mode
	if gin.Mode() == gin.ReleaseMode {
		gin.DefaultWriter = io.Discard
	}

	// init routers
	router := gin.New()
	router.RedirectTrailingSlash = false
	router.Use(
		gin.LoggerWithWriter(gin.DefaultWriter),
		gin.Recovery(),
	)

	// add default compression
	router.Use(gzip.Gzip(gzip.DefaultCompression))

	// cors configuration only in debug mode GIN_MODE=debug (default)
	if gin.Mode() == gin.DebugMode {
		// gin gonic cors conf
		corsConf := cors.DefaultConfig()
		corsConf.AllowHeaders = []string{"Authorization", "Content-Type", "Accept"}
		corsConf.AllowAllOrigins = true
		router.Use(cors.New(corsConf))
	}

	// define api group
	api := router.Group("/")

	api.POST("/login", middleware.InstanceJWT().LoginHandler)
	api.POST("/logout", middleware.InstanceJWT().LogoutHandler)

	// 2FA APIs
	api.POST("/2fa/otp-verify", methods.OTPVerify)

	// Test endpoint (not authenticated)
	api.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "healthy",
			"status":  "ok",
		})
	})

	// define websocket endpoint (before JWT middleware)
	api.GET("/ws/", socket.WsProxyHandler)

	api.Use(middleware.InstanceJWT().MiddlewareFunc())
	{
		// 2FA APIs
		api.GET("/2fa", methods.Get2FAStatus)
		api.DELETE("/2fa", methods.Disable2FA)
		api.GET("/2fa/recovery-codes", methods.Get2FARecoveryCodes)
		api.GET("/2fa/qr-code", methods.QRCode)

		// Phone Island Integration APIs
		api.POST("/authentication/phone_island_token_login", methods.PhoneIslandTokenLogin)
		api.POST("/authentication/persistent_token_remove", methods.PhoneIslandTokenRemove)
		api.GET("/authentication/phone_island_token_check", methods.PhoneIslandTokenCheck)

		// Test endpoint (authenticated)
		api.GET("/auth-health", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{
				"message": "healthy",
				"status":  "ok",
			})
		})
	}

	// handle missing endpoint
	router.NoRoute(middleware.InstanceJWT().MiddlewareFunc(), func(c *gin.Context) {
		// Fallback to proxy logic for legacy V1 API
		methods.ProxyV1Request(c, c.Request.URL.Path)
	})

	return router
}
