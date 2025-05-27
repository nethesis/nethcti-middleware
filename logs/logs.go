/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package logs

import (
	"log"
	"os"
	"strings"

	"github.com/nethesis/nethcti-middleware/configuration"
)

var Logs *log.Logger

func Init(name string) {
	// init syslog writer
	logger := log.New(os.Stderr, name+" ", log.Ldate|log.Ltime|log.Lshortfile)

	// assign writer to Logs var
	Logs = logger
}

func Log(message string) {
	Logs.Println(message)
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
	logger.Println("[CONFIG] NETHVOICE_MIDDLEWARE_V1_WS_PATH: " + strings.Join(Config.SensitiveList, ","))
	if Config.Secret_jwt != "" {
		logger.Println("[CONFIG] NETHVOICE_MIDDLEWARE_SECRET_JWT: set")
	} else {
		logger.Println("[CONFIG] NETHVOICE_MIDDLEWARE_SECRET_JWT: not set")
	}
	logger.Print("\n=================================================\n\n")
}
