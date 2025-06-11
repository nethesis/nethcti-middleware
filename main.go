/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package main

import (
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/fatih/structs"
	"github.com/gin-contrib/cors"
	"github.com/gin-contrib/gzip"
	"github.com/gin-gonic/gin"
	"github.com/robfig/cron/v3"

	"github.com/nethesis/nethcti-middleware/configuration"
	"github.com/nethesis/nethcti-middleware/logs"
	"github.com/nethesis/nethcti-middleware/methods"
	"github.com/nethesis/nethcti-middleware/middleware"
	"github.com/nethesis/nethcti-middleware/response"
	"github.com/nethesis/nethcti-middleware/socket"
	"github.com/nethesis/nethcti-middleware/store"
)

func main() {
	// init logger
	logs.Init("nethcti-middleware")

	// init configuration
	configuration.Init()
	LogConfig(configuration.Config)

	// init store
	store.UserSessionInit()

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

	api.Use(middleware.InstanceJWT().MiddlewareFunc())
	{
		// 2FA APIs
		api.GET("/2fa", methods.Get2FAStatus)
		api.DELETE("/2fa", methods.Disable2FA)
		api.GET("/2fa/recovery-codes", methods.Get2FARecoveryCodes)
		api.GET("/2fa/qr-code", methods.QRCode)
	}

	// define websocket endpoint
	ws := router.Group(configuration.Config.V1WsPath)
	ws.GET("/", socket.WsProxyHandler)

	// handle missing endpoint
	router.NoRoute(middleware.InstanceJWT().MiddlewareFunc(), func(c *gin.Context) {
		// Check if the requested API exists on the current server
		if c.Request.Method == http.MethodGet || c.Request.Method == http.MethodPost {
			// Fallback to proxy logic for legacy V1 API
			methods.ProxyV1Request(c, c.Request.URL.Path)
			return
		}

		// If not handled, return 404
		c.JSON(http.StatusNotFound, structs.Map(response.StatusNotFound{
			Code:    404,
			Message: "API not found",
			Data:    nil,
		}))
	})

	// create cron to run daily
	c := cron.New()
	c.AddFunc("@daily", methods.DeleteExpiredTokens)
	c.Start()

	// run server
	router.Run(configuration.Config.ListenAddress)
}

func LogConfig(Config configuration.Configuration) {

	logger := log.New(os.Stderr, "", 0)

	// log environment variables
	logger.Print("\n================= CONFIGURATION =================\n\n")
	logger.Println("[CONFIG] NETHVOICE_MIDDLEWARE_LISTEN_ADDRESS: " + Config.ListenAddress)
	logger.Println("[CONFIG] NETHVOICE_MIDDLEWARE_V1_PROTOCOL: " + Config.V1Protocol)
	logger.Println("[CONFIG] NETHVOICE_MIDDLEWARE_V1_API_ENDPOINT: " + Config.V1ApiEndpoint)
	logger.Println("[CONFIG] NETHVOICE_MIDDLEWARE_V1_WS_ENDPOINT: " + Config.V1WsEndpoint)
	logger.Println("[CONFIG] NETHVOICE_MIDDLEWARE_V1_API_PATH: " + Config.V1ApiPath)
	logger.Println("[CONFIG] NETHVOICE_MIDDLEWARE_V1_WS_PATH: " + Config.V1WsPath)
	logger.Println("[CONFIG] NETHVOICE_MIDDLEWARE_SENSITIVE_LIST: " + strings.Join(Config.SensitiveList, ","))
	if Config.Secret_jwt != "" {
		logger.Println("[CONFIG] NETHVOICE_MIDDLEWARE_SECRET_JWT: set")
	} else {
		logger.Println("[CONFIG] NETHVOICE_MIDDLEWARE_SECRET_JWT: not set")
	}
	logger.Print("\n=================================================\n\n")
}
