/*
 * Copyright (C) 2026 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package methods

import (
	"context"
	"crypto/sha1"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/nethesis/nethcti-middleware/configuration"
	"github.com/nethesis/nethcti-middleware/db"
	"github.com/nethesis/nethcti-middleware/logs"
)

// getFreePBXUserSHA1Password queries the asterisk.ampusers table for a user's SHA1 password hash.
func getFreePBXUserSHA1Password(username string) (string, error) {
	database := db.GetDB()
	if database == nil {
		return "", fmt.Errorf("database connection not available")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var sha1Pwd string
	err := database.QueryRowContext(ctx,
		"SELECT `password_sha1` FROM `asterisk`.`ampusers` WHERE `username` = ?",
		username,
	).Scan(&sha1Pwd)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("user %q not found in ampusers", username)
		}
		return "", fmt.Errorf("query ampusers for %q: %w", username, err)
	}

	return sha1Pwd, nil
}

// computeFreePBXSecretKey computes SHA1(username + sha1Password + secretKey).
func computeFreePBXSecretKey(username, sha1Pwd, secret string) string {
	h := sha1.New()
	h.Write([]byte(username + sha1Pwd + secret))
	return hex.EncodeToString(h.Sum(nil))
}

// RewriteSupportToAdmin validates a support user's Secretkey against MariaDB
// and rewrites the request headers to use admin credentials.
// Returns true if the rewrite succeeded, false otherwise (caller should return 401).
func RewriteSupportToAdmin(c *gin.Context) bool {
	username := c.GetHeader("User")
	secretKey := c.GetHeader("Secretkey")
	secret := configuration.Config.NethVoiceSecretKey

	if secret == "" {
		logs.Log("[ERROR][FREEPBX_AUTH] NETHVOICESECRETKEY not configured, cannot validate support user")
		return false
	}

	// Validate the support user's Secretkey
	userSHA1, err := getFreePBXUserSHA1Password(username)
	if err != nil {
		logs.Log(fmt.Sprintf("[WARN][FREEPBX_AUTH] failed to get SHA1 password for %q: %v", username, err))
		return false
	}

	expectedKey := computeFreePBXSecretKey(username, userSHA1, secret)
	if secretKey != expectedKey {
		logs.Log(fmt.Sprintf("[WARN][FREEPBX_AUTH] invalid Secretkey for support user %q", username))
		return false
	}

	// Compute admin's Secretkey
	adminSHA1, err := getFreePBXUserSHA1Password("admin")
	if err != nil {
		logs.Log(fmt.Sprintf("[ERROR][FREEPBX_AUTH] failed to get admin SHA1 password: %v", err))
		return false
	}

	adminSecretKey := computeFreePBXSecretKey("admin", adminSHA1, secret)

	// Rewrite headers
	c.Request.Header.Set("User", "admin")
	c.Request.Header.Set("Secretkey", adminSecretKey)

	logs.Log(fmt.Sprintf("[INFO][FREEPBX_AUTH] rewrote headers for support user %q -> admin", username))
	return true
}

// IsSupportUser returns true if the User header starts with "support-" and Secretkey is present.
func IsSupportUser(c *gin.Context) bool {
	return strings.HasPrefix(c.GetHeader("User"), "support-") && c.GetHeader("Secretkey") != ""
}
