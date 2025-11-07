/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/nethesis/nethcti-middleware/logs"
	"github.com/nethesis/nethcti-middleware/models"
)

// PersistedSession represents minimal session data needed for persistence
type PersistedSession struct {
	Username     string   `json:"username"`
	JWTTokens    []string `json:"jwt_tokens"`
	NethCTIToken string   `json:"nethcti_token"`
}

var (
	persistenceMutex sync.RWMutex
	persistencePath  string
)

// InitPersistence sets up the persistence file path
func InitPersistence(dataDir string) {
	persistencePath = filepath.Join(dataDir, "sessions.json")
	logs.Log("[INFO][PERSISTENCE] Session persistence initialized at " + persistencePath)
}

// SaveSessions saves current user sessions to disk
func SaveSessions() error {
	if persistencePath == "" {
		return nil // Persistence not initialized
	}

	persistenceMutex.Lock()
	defer persistenceMutex.Unlock()

	// Convert UserSessions to PersistedSession format
	sessions := make([]PersistedSession, 0, len(UserSessions))
	for username, session := range UserSessions {
		sessions = append(sessions, PersistedSession{
			Username:     username,
			JWTTokens:    session.JWTTokens,
			NethCTIToken: session.NethCTIToken,
		})
	}

	// Marshal to JSON
	data, err := json.MarshalIndent(sessions, "", "  ")
	if err != nil {
		logs.Log("[ERROR][PERSISTENCE] Failed to marshal sessions: " + err.Error())
		return err
	}

	// Ensure directory exists
	dir := filepath.Dir(persistencePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		logs.Log("[ERROR][PERSISTENCE] Failed to create directory: " + err.Error())
		return err
	}

	// Write to file atomically (write to temp file, then rename)
	tempPath := persistencePath + ".tmp"
	if err := os.WriteFile(tempPath, data, 0600); err != nil {
		logs.Log("[ERROR][PERSISTENCE] Failed to write sessions file: " + err.Error())
		return err
	}

	if err := os.Rename(tempPath, persistencePath); err != nil {
		logs.Log("[ERROR][PERSISTENCE] Failed to rename sessions file: " + err.Error())
		os.Remove(tempPath) // Cleanup
		return err
	}

	return nil
}

// LoadSessions loads user sessions from disk
func LoadSessions() error {
	if persistencePath == "" {
		return nil // Persistence not initialized
	}

	persistenceMutex.RLock()
	defer persistenceMutex.RUnlock()

	// Check if file exists
	if _, err := os.Stat(persistencePath); os.IsNotExist(err) {
		logs.Log("[INFO][PERSISTENCE] No persisted sessions found (first run)")
		return nil
	}

	// Read file
	data, err := os.ReadFile(persistencePath)
	if err != nil {
		logs.Log("[ERROR][PERSISTENCE] Failed to read sessions file: " + err.Error())
		return err
	}

	// Unmarshal JSON
	var sessions []PersistedSession
	if err := json.Unmarshal(data, &sessions); err != nil {
		logs.Log("[ERROR][PERSISTENCE] Failed to unmarshal sessions: " + err.Error())
		return err
	}

	// Restore sessions to UserSessions map
	loadedCount := 0
	for _, ps := range sessions {
		// Recreate UserSession
		UserSessions[ps.Username] = &models.UserSession{
			Username:     ps.Username,
			JWTTokens:    ps.JWTTokens,
			NethCTIToken: ps.NethCTIToken,
			OTP_Verified: false, // Will be validated from JWT claims
		}
		loadedCount++
	}

	logs.Log(fmt.Sprintf("[INFO][PERSISTENCE] Loaded %d session(s) from disk", loadedCount))
	return nil
}
