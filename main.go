/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package main

import (
	"io"
	"net/http"

	"github.com/fatih/structs"
	"github.com/gin-contrib/cors"
	"github.com/gin-contrib/gzip"
	"github.com/gin-gonic/gin"

	"github.com/nethesis/nethcti-middleware/configuration"
	"github.com/nethesis/nethcti-middleware/logs"
	"github.com/nethesis/nethcti-middleware/methods"
	"github.com/nethesis/nethcti-middleware/middleware"
	"github.com/nethesis/nethcti-middleware/response"
	"github.com/nethesis/nethcti-middleware/socket"
)

func main() {
	// init configuration
	configuration.Init()

	// init logger
	logs.Init("nethcti-middleware")
	logs.LogConfig(configuration.Config)

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

	api.Use(middleware.InstanceJWT().MiddlewareFunc())
	{
		// define v1 api group
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

	// run server
	router.Run(configuration.Config.ListenAddress)
}
