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
	V1Endpoint    string `json:"v1_endpoint"`
	V1Path        string `json:"v1_path"`
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

	// set V1 API endpoint
	if os.Getenv("V1_ENDPOINT") != "" {
		Config.V1Endpoint = os.Getenv("V1_ENDPOINT")
	} else {
		Config.V1Endpoint = "https://cti2.demo-heron.sf.nethserver.net"
	}

	// set V1 API path
	if os.Getenv("V1_PATH") != "" {
		Config.V1Path = os.Getenv("V1_PATH")
	} else {
		Config.V1Path = "/webrest"
	}
}
