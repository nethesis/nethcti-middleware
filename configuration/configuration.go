/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package configuration

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"github.com/nethesis/nethcti-middleware/logs"
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
	FreePBXAPIs   []string `json:"freepbx_apis"`

	SecretsDir string `json:"secrets_dir"`
	Issuer2FA  string `json:"issuer_2fa"`

	// MQTT Configuration for satellite transcriptions
	MQTTHost     string `json:"mqtt_host"`
	MQTTPort     string `json:"mqtt_port"`
	MQTTUsername string `json:"mqtt_username"`
	MQTTPassword string `json:"mqtt_password"`
	MQTTEnabled  bool   `json:"mqtt_enabled"`

	// Middleware MariaDB Configuration for phonebook and persistence layer
	MiddlewareMariaDBHost     string `json:"nethvoice_middleware_mariadb_host"`
	MiddlewareMariaDBPort     string `json:"nethvoice_middleware_mariadb_port"`
	MiddlewareMariaDBUser     string `json:"nethvoice_middleware_mariadb_user"`
	MiddlewareMariaDBPassword string `json:"nethvoice_middleware_mariadb_password"`
	MiddlewareMariaDBDatabase string `json:"nethvoice_middleware_mariadb_database"`
}

var Config = Configuration{}

// loadOrGenerateJWTSecret loads JWT secret from file or generates a new one if it doesn't exist
func loadOrGenerateJWTSecret(secretsDir string) string {
	jwtSecretPath := filepath.Join(secretsDir, "jwt.secret")

	// Try to read existing secret
	if data, err := os.ReadFile(jwtSecretPath); err == nil {
		secret := strings.TrimSpace(string(data))
		if secret != "" {
			logs.Log("[INFO][CONFIG] Loaded existing JWT secret from " + jwtSecretPath)
			return secret
		}
	}

	// Generate new secret if file doesn't exist or is empty
	newSecret := uuid.New().String()

	// Ensure directory exists
	if err := os.MkdirAll(secretsDir, 0700); err != nil {
		logs.Log("[WARNING][CONFIG] Failed to create secrets directory: " + err.Error() + ", using in-memory secret")
		return newSecret
	}

	// Write secret to file
	if err := os.WriteFile(jwtSecretPath, []byte(newSecret), 0600); err != nil {
		logs.Log("[WARNING][CONFIG] Failed to save JWT secret to file: " + err.Error() + ", using in-memory secret")
		return newSecret
	}

	logs.Log("[INFO][CONFIG] Generated and saved new JWT secret to " + jwtSecretPath)
	return newSecret
}

func Init() {
	// read configuration from ENV
	if os.Getenv("NETHVOICE_MIDDLEWARE_LISTEN_ADDRESS") != "" {
		Config.ListenAddress = os.Getenv("NETHVOICE_MIDDLEWARE_LISTEN_ADDRESS")
	} else {
		Config.ListenAddress = "127.0.0.1:8080"
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
		logs.Log("[CRITICAL][ENV] NETHVOICE_MIDDLEWARE_V1_API_ENDPOINT variable is empty")
		os.Exit(1)
	}

	// set V1 API endpoint
	if os.Getenv("NETHVOICE_MIDDLEWARE_V1_WS_ENDPOINT") != "" {
		Config.V1WsEndpoint = os.Getenv("NETHVOICE_MIDDLEWARE_V1_WS_ENDPOINT")
	} else {
		logs.Log("[CRITICAL][ENV] NETHVOICE_MIDDLEWARE_V1_WS_ENDPOINT variable is empty")
		os.Exit(1)
	}

	// set V1 API path
	if os.Getenv("NETHVOICE_MIDDLEWARE_V1_API_PATH") != "" {
		Config.V1ApiPath = os.Getenv("NETHVOICE_MIDDLEWARE_V1_API_PATH")
	} else {
		Config.V1ApiPath = ""
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

	// set secrets dir
	if os.Getenv("NETHVOICE_MIDDLEWARE_SECRETS_DIR") != "" {
		Config.SecretsDir = os.Getenv("NETHVOICE_MIDDLEWARE_SECRETS_DIR")
	} else {
		Config.SecretsDir = "/var/lib/whale/secrets"
	}

	// set issuer for 2FA
	if os.Getenv("NETHVOICE_MIDDLEWARE_ISSUER_2FA") != "" {
		Config.Issuer2FA = os.Getenv("NETHVOICE_MIDDLEWARE_ISSUER_2FA")
	} else {
		Config.Issuer2FA = "NethVoice"
	}

	// set FreePBX APIs (FreePBX admin APIs that bypass JWT)
	if os.Getenv("NETHVOICE_MIDDLEWARE_FREEPBX_APIS") != "" {
		Config.FreePBXAPIs = strings.Split(os.Getenv("NETHVOICE_MIDDLEWARE_FREEPBX_APIS"), ",")
	} else {
		Config.FreePBXAPIs = []string{
			"/dbconn/test",
			"/custcard/preview",
			"/user/endpoints/all",
			"/user/presence",
			"/astproxy/extension",
			"/astproxy/extensions",
			"/astproxy/trunk",
			"/astproxy/trunks",
		}
	}

	// set MQTT configuration for satellite transcriptions
	if os.Getenv("SATELLITE_MQTT_HOST") != "" {
		Config.MQTTHost = os.Getenv("SATELLITE_MQTT_HOST")
	} else {
		Config.MQTTHost = "127.0.0.1"
	}

	if os.Getenv("SATELLITE_MQTT_PORT") != "" {
		Config.MQTTPort = os.Getenv("SATELLITE_MQTT_PORT")
	} else {
		Config.MQTTPort = "1883"
	}

	if os.Getenv("SATELLITE_MQTT_USERNAME") != "" {
		Config.MQTTUsername = os.Getenv("SATELLITE_MQTT_USERNAME")
	} else {
		Config.MQTTUsername = "satellite"
	}

	if os.Getenv("SATELLITE_MQTT_PASSWORD") != "" {
		Config.MQTTPassword = os.Getenv("SATELLITE_MQTT_PASSWORD")
	}

	// Enable MQTT only if we have at least username and password
	Config.MQTTEnabled = Config.MQTTUsername != "" && Config.MQTTPassword != ""

	// Load or generate JWT secret
	Config.Secret_jwt = loadOrGenerateJWTSecret(Config.SecretsDir)

	// Set MariaDB host
	if os.Getenv("NETHVOICE_MIDDLEWARE_MARIADB_HOST") != "" {
		Config.MiddlewareMariaDBHost = os.Getenv("NETHVOICE_MIDDLEWARE_MARIADB_HOST")
	} else {
		Config.MiddlewareMariaDBHost = "localhost"
	}

	// Set MariaDB user
	if os.Getenv("NETHVOICE_MIDDLEWARE_MARIADB_USER") != "" {
		Config.MiddlewareMariaDBUser = os.Getenv("NETHVOICE_MIDDLEWARE_MARIADB_USER")
	} else {
		Config.MiddlewareMariaDBUser = "root"
	}

	// Set MariaDB port (default to 3306 when not provided)
	if os.Getenv("NETHVOICE_MIDDLEWARE_MARIADB_PORT") != "" {
		Config.MiddlewareMariaDBPort = os.Getenv("NETHVOICE_MIDDLEWARE_MARIADB_PORT")
	} else {
		// Default to standard MariaDB port for local testing/environments
		Config.MiddlewareMariaDBPort = "3306"
		logs.Log("[WARN][ENV] NETHVOICE_MIDDLEWARE_MARIADB_PORT not set; defaulting to 3306")
	}

	// Set MariaDB password (default to 'root' for local test environments)
	if os.Getenv("NETHVOICE_MIDDLEWARE_MARIADB_PASSWORD") != "" {
		Config.MiddlewareMariaDBPassword = os.Getenv("NETHVOICE_MIDDLEWARE_MARIADB_PASSWORD")
	} else {
		Config.MiddlewareMariaDBPassword = "root"
		logs.Log("[WARN][ENV] NETHVOICE_MIDDLEWARE_MARIADB_PASSWORD not set; defaulting to 'root' for local testing")
	}

	// Set MariaDB database name
	if os.Getenv("NETHVOICE_MIDDLEWARE_MARIADB_DATABASE") != "" {
		Config.MiddlewareMariaDBDatabase = os.Getenv("NETHVOICE_MIDDLEWARE_MARIADB_DATABASE")
	} else {
		Config.MiddlewareMariaDBDatabase = "nethcti3"
	}
}
