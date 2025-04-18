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
}
