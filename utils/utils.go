/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package utils

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"net/http"
	"strings"
)

func GenerateLegacyToken(res *http.Response, username, password string) string {
	wwwAuth := res.Header.Get("Www-Authenticate")
	parts := strings.Split(wwwAuth, " ")
	if len(parts) < 2 {
		return ""
	}

	nonce := parts[1]
	message := username + ":" + password + ":" + nonce

	mac := hmac.New(sha1.New, []byte(password))
	mac.Write([]byte(message))
	token := hex.EncodeToString(mac.Sum(nil))

	token = username + ":" + token

	return token
}
