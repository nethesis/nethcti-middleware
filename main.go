/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package main

import (
	"io"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"

	"github.com/gin-contrib/cors"
	"github.com/gin-contrib/gzip"
	"github.com/gin-gonic/gin"
	"github.com/robfig/cron/v3"

	"github.com/nethesis/nethcti-middleware/configuration"
	"github.com/nethesis/nethcti-middleware/db"
	"github.com/nethesis/nethcti-middleware/logs"
	"github.com/nethesis/nethcti-middleware/methods"
	"github.com/nethesis/nethcti-middleware/middleware"
	"github.com/nethesis/nethcti-middleware/mqtt"
	"github.com/nethesis/nethcti-middleware/socket"
	"github.com/nethesis/nethcti-middleware/store"
)

func main() {
	// Init logger first
	logs.Init("nethcti-middleware")

	// Init configuration
	configuration.Init()

	// Init database
	err := db.Init()
	if err != nil {
		logs.Log("[CRITICAL] Failed to initialize database: " + err.Error())
		return
	}
	defer db.Close()

	// Init store
	store.UserSessionInit()

	store.InitPersistence(configuration.Config.SecretsDir)
	if err := store.LoadSessions(); err != nil {
		logs.Log("[WARNING][PERSISTENCE] Failed to load sessions: " + err.Error())
	}

	// Init authorization profiles
	if err := store.InitProfiles(configuration.Config.ProfilesConfigPath, configuration.Config.UsersConfigPath); err != nil {
		logs.Log("[CRITICAL] Failed to initialize authorization profiles: " + err.Error())
		return
	}

	// Setup signal handler for SIGUSR1 to reload profiles
	go setupSignalHandler()

	// Init MQTT and setup transcription subscription
	mqttCh := mqtt.Init()
	if mqttCh != nil {
		socket.SetMQTTChannel(mqttCh)
		err := mqtt.InitTranscriptionSubscription()
		if err != nil {
			logs.Log("[WARNING][MQTT] Failed to subscribe to transcription topic: " + err.Error())
		}
	}

	// Create router
	router := createRouter()

	// Create cron to run daily
	c := cron.New()
	c.AddFunc("@daily", methods.DeleteExpiredTokens)
	c.Start()

	// Run server
	router.Run(configuration.Config.ListenAddress)
}

// broadcastReloadNotification is a middleware that broadcasts profile reload notification to all connected clients via WebSocket
func broadcastReloadNotification() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check if broadcast flag was set by SuperAdminReload
		if broadcast, exists := c.Get("broadcast_reload"); exists && broadcast.(bool) {
			// Broadcast notification to all connected WebSocket clients
			socket.GetConnectionManager().BroadcastGlobal("profile_reload_global", gin.H{
				"trigger": "api",
			})
		}
	}
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

	// Super admin reload endpoint (no JWT required)
	api.POST("/admin/reload", middleware.RequireSuperAdmin(), methods.SuperAdminReload, broadcastReloadNotification())

	// Authentication required endpoints
	api.Use(middleware.InstanceJWT().MiddlewareFunc())
	{
		// 2FA APIs
		api.POST("/2fa/disable", methods.Disable2FA)
		api.POST("/2fa/verify-otp", methods.VerifyOTP)
		api.GET("/2fa/status", methods.Get2FAStatus)
		api.POST("/2fa/recovery-codes", methods.Get2FARecoveryCodes)
		api.GET("/2fa/qr-code", methods.QRCode)

		// Phonebook APIs
		api.POST("/phonebook/import", middleware.RequireCapabilities("phonebook.ad_phonebook"), methods.ImportPhonebookCSV)

		// Phone Island Integration APIs
		api.POST("/authentication/phone_island_token_login", methods.PhoneIslandTokenLogin)
		api.POST("/authentication/persistent_token_remove", methods.PhoneIslandTokenRemove)
		api.GET("/authentication/phone_island_token_check", methods.PhoneIslandTokenCheck)

		// Token refresh endpoint
		api.POST("/refresh", methods.ReloadProfileAndToken)

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

		// Check if the API is in the FreePBX API list (prefix match with validation)
		isFreePBXAPI := false
		for _, freepbxPath := range configuration.Config.FreePBXAPIs {
			if path == freepbxPath {
				// Exact match
				isFreePBXAPI = true
				break
			} else if strings.HasPrefix(path, freepbxPath+"/") {
				// Prefix match - validate the remainder contains only numeric ID or safe paths
				remainder := path[len(freepbxPath)+1:]
				// Allow only numeric IDs (extensions/trunks) - no path traversal or additional paths
				matched, _ := regexp.MatchString(`^\d+$`, remainder)
				if matched {
					isFreePBXAPI = true
					break
				}
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

// setupSignalHandler sets up SIGUSR1 listener for profile reload
func setupSignalHandler() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGUSR1)

	for range sigChan {
		logs.Log("[SIGNAL] Received SIGUSR1 signal, reloading profiles...")
		if err := store.ReloadProfiles(); err != nil {
			logs.Log("[SIGNAL][ERROR] Failed to reload profiles on SIGUSR1: " + err.Error())
		} else {
			logs.Log("[SIGNAL] Profile reload completed successfully from SIGUSR1")
			// Broadcast notification to all connected users via WebSocket
			socket.GetConnectionManager().BroadcastGlobal("profile_reload_global", gin.H{
				"trigger": "signal",
			})
		}
	}
}
