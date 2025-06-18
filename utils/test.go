/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package utils

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
)

func PerformLogin(testServerURL string) string {
	loginData := map[string]string{
		"username": "testuser",
		"password": "testpass",
	}
	jsonData, _ := json.Marshal(loginData)

	resp, err := http.Post(testServerURL+"/login", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	var response map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&response)
	return response["token"].(string)
}

func Setup2FA(username string) {
	// Create user directory
	userDir := "/tmp/test-secrets/" + username
	os.MkdirAll(userDir, 0700)

	// Create secret file
	secretFile := userDir + "/secret"
	os.WriteFile(secretFile, []byte("JBSWY3DPEHPK3PXP"), 0600)

	// Set initial status to disabled
	statusFile := userDir + "/status"
	os.WriteFile(statusFile, []byte("0"), 0600)
}

func Enable2FA(username string) {
	statusFile := "/tmp/test-secrets/" + username + "/status"
	os.WriteFile(statusFile, []byte("1"), 0600)
}

// decodeJWTPart decodes a JWT base64url part
func DecodeJWTPart(part string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		decoded, err = base64.URLEncoding.DecodeString(part)
	}
	return decoded, err
}
