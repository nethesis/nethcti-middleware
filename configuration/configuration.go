/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package configuration

import (
	"os"
	"strings"

	"github.com/google/uuid"
)

type Configuration struct {
	ListenAddress string   `json:"listen_address"`
	Secret_jwt    string   `json:"secret"`
	V1Protocol    string   `json:"v1_protocol"`
	V1ApiEndpoint string   `json:"v1_api_endpoint"`
	V1WsEndpoint  string   `json:"v1_ws_endpoint"`
	V1ApiPath     string   `json:"v1_api_path"`
	V1WsPath      string   `json:"v1_ws_path"`
	SensitiveList []string `json:"sensitive_list"`
}

var Config = Configuration{}

func Init() {
	// read configuration from ENV
	if os.Getenv("NETHVOICE_MIDDLEWARE_LISTEN_ADDRESS") != "" {
		Config.ListenAddress = os.Getenv("NETHVOICE_MIDDLEWARE_LISTEN_ADDRESS")
	} else {
		Config.ListenAddress = "127.0.0.1:8080"
	}

	// set default secret
	if os.Getenv("NETHVOICE_MIDDLEWARE_SECRET_JWT") != "" {
		Config.Secret_jwt = os.Getenv("NETHVOICE_MIDDLEWARE_SECRET_JWT")
	} else {
		Config.Secret_jwt = uuid.New().String()
	}

	// set V1 API protocol
	if os.Getenv("NETHVOICE_MIDDLEWARE_V1_PROTOCOL") != "" {
		Config.V1Protocol = os.Getenv("NETHVOICE_MIDDLEWARE_V1_PROTOCOL")
	} else {
		Config.V1Protocol = "https"
	}

	// set V1 API endpoint
	if os.Getenv("NETHVOICE_MIDDLEWARE_V1_API_ENDPOINT") != "" {
		Config.V1ApiEndpoint = os.Getenv("NETHVOICE_MIDDLEWARE_V1_API_ENDPOINT")
	} else {
		Config.V1ApiEndpoint = "cti2.demo-heron.sf.nethserver.net"
	}

	// set V1 API endpoint
	if os.Getenv("NETHVOICE_MIDDLEWARE_V1_WS_ENDPOINT") != "" {
		Config.V1WsEndpoint = os.Getenv("NETHVOICE_MIDDLEWARE_V1_WS_ENDPOINT")
	} else {
		Config.V1WsEndpoint = "cti2.demo-heron.sf.nethserver.net"
	}

	// set V1 API path
	if os.Getenv("NETHVOICE_MIDDLEWARE_V1_API_PATH") != "" {
		Config.V1ApiPath = os.Getenv("NETHVOICE_MIDDLEWARE_V1_API_PATH")
	} else {
		Config.V1ApiPath = "/webrest"
	}

	// set V1 API path
	if os.Getenv("NETHVOICE_MIDDLEWARE_V1_WS_PATH") != "" {
		Config.V1WsPath = os.Getenv("NETHVOICE_MIDDLEWARE_V1_WS_PATH")
	} else {
		Config.V1WsPath = "/socket.io"
	}

	// set sensitive list
	if os.Getenv("NETHVOICE_MIDDLEWARE_SENSITIVE_LIST") != "" {
		Config.SensitiveList = strings.Split(os.Getenv("NETHVOICE_MIDDLEWARE_SENSITIVE_LIST"), ",")
	} else {
		Config.SensitiveList = []string{"password", "secret", "token", "passphrase", "private", "key"}
	}
}
