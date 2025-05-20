/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package configuration

import (
	"os"
)

type Configuration struct {
	ListenAddress string `json:"listen_address"`
	Secret        string `json:"secret"`
	AuditFile     string `json:"audit_file"`
	V1Protocol    string `json:"v1_protocol"`
	V1ApiEndpoint string `json:"v1_api_endpoint"`
	V1WsEndpoint  string `json:"v1_ws_endpoint"`
	V1ApiPath     string `json:"v1_api_path"`
	V1WsPath      string `json:"v1_ws_path"`
}

var Config = Configuration{}

func Init() {
	// read configuration from ENV
	if os.Getenv("LISTEN_ADDRESS") != "" {
		Config.ListenAddress = os.Getenv("LISTEN_ADDRESS")
	} else {
		Config.ListenAddress = "127.0.0.1:8080"
	}

	// set default secret
	if os.Getenv("SECRET") != "" {
		Config.Secret = os.Getenv("SECRET")
	} else {
		os.Stderr.WriteString("SECRET variable is empty. ")
		os.Exit(1)
	}

	// set default audit file
	if os.Getenv("AUDIT_FILE") != "" {
		Config.AuditFile = os.Getenv("AUDIT_FILE")
	} else {
		Config.AuditFile = ""
	}

	// set V1 API protocol
	if os.Getenv("V1_PROTOCOL") != "" {
		Config.V1Protocol = os.Getenv("V1_PROTOCOL")
	} else {
		Config.V1Protocol = "https"
	}

	// set V1 API endpoint
	if os.Getenv("V1_API_ENDPOINT") != "" {
		Config.V1ApiEndpoint = os.Getenv("V1_API_ENDPOINT")
	} else {
		Config.V1ApiEndpoint = "cti2.demo-heron.sf.nethserver.net"
	}

	// set V1 API endpoint
	if os.Getenv("V1_WS_ENDPOINT") != "" {
		Config.V1WsEndpoint = os.Getenv("V1_WS_ENDPOINT")
	} else {
		Config.V1WsEndpoint = "cti2.demo-heron.sf.nethserver.net"
	}

	// set V1 API path
	if os.Getenv("V1_API_PATH") != "" {
		Config.V1ApiPath = os.Getenv("V1_API_PATH")
	} else {
		Config.V1ApiPath = "/webrest"
	}

	// set V1 API path
	if os.Getenv("V1_WS_PATH") != "" {
		Config.V1WsPath = os.Getenv("V1_WS_PATH")
	} else {
		Config.V1WsPath = "/socket.io"
	}
}
