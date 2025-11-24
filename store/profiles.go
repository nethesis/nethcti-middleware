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
)

// ProfileData represents a profile with capability map
type ProfileData struct {
	ID           string
	Name         string
	Capabilities map[string]bool
}

// UserProfile links a username to a profile
type UserProfile struct {
	Username  string
	ProfileID string
}

type rawProfile struct {
	ID               string                         `json:"id"`
	Name             string                         `json:"name"`
	MacroPermissions map[string]*rawMacroPermission `json:"macro_permissions"`
}

type rawMacroPermission struct {
	Value       bool             `json:"value"`
	Permissions []*rawPermission `json:"permissions"`
}

type rawPermission struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Value bool   `json:"value"`
}

type rawUser struct {
	ProfileID string `json:"profile_id"`
}

var (
	profiles     map[string]*ProfileData
	users        map[string]*UserProfile
	profileMutex sync.RWMutex
)

// InitProfiles loads profiles and users from JSON files
func InitProfiles(profilesPath, usersPath string) error {
	profAbs, err := filepath.Abs(profilesPath)
	if err != nil {
		return fmt.Errorf("profiles path: %w", err)
	}

	usersAbs, err := filepath.Abs(usersPath)
	if err != nil {
		return fmt.Errorf("users path: %w", err)
	}

	if err := loadProfiles(profAbs); err != nil {
		return err
	}

	if err := loadUsers(usersAbs); err != nil {
		return err
	}

	return nil
}

// GetUserCapabilities returns all capabilities for a given username
func GetUserCapabilities(username string) (map[string]bool, error) {
	profileMutex.RLock()
	defer profileMutex.RUnlock()

	user, ok := users[username]
	if !ok {
		return nil, fmt.Errorf("user %s not found", username)
	}

	profile, ok := profiles[user.ProfileID]
	if !ok {
		return nil, fmt.Errorf("profile %s not found for user %s", user.ProfileID, username)
	}

	return profile.Capabilities, nil
}

// GetUserProfile returns the profile data for a given username
func GetUserProfile(username string) (*ProfileData, error) {
	profileMutex.RLock()
	defer profileMutex.RUnlock()

	user, ok := users[username]
	if !ok {
		return nil, fmt.Errorf("user %s not found", username)
	}

	profile, ok := profiles[user.ProfileID]
	if !ok {
		return nil, fmt.Errorf("profile %s not found for user %s", user.ProfileID, username)
	}

	return profile, nil
}

func loadProfiles(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read profiles: %w", err)
	}

	raw := make(map[string]*rawProfile)
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("parse profiles: %w", err)
	}

	profileMutex.Lock()
	defer profileMutex.Unlock()

	profiles = make(map[string]*ProfileData)
	for key, rp := range raw {
		profID := rp.ID
		if profID == "" {
			profID = key
		}

		if profID == "" {
			continue
		}

		capMap := make(map[string]bool)
		for macroName, macro := range rp.MacroPermissions {
			capMap[macroName+".value"] = macro.Value
			for _, permission := range macro.Permissions {
				key := fmt.Sprintf("%s.%s", macroName, permission.Name)
				capMap[key] = permission.Value
			}
		}

		profiles[profID] = &ProfileData{
			ID:           profID,
			Name:         rp.Name,
			Capabilities: capMap,
		}
	}

	logs.Log(fmt.Sprintf("[AUTHZ] loaded %d profiles", len(profiles)))
	return nil
}

func loadUsers(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read users: %w", err)
	}

	raw := make(map[string]*rawUser)
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("parse users: %w", err)
	}

	profileMutex.Lock()
	defer profileMutex.Unlock()

	users = make(map[string]*UserProfile)
	for username, ru := range raw {
		if ru.ProfileID == "" {
			return fmt.Errorf("user %s missing profile reference", username)
		}

		if _, ok := profiles[ru.ProfileID]; !ok {
			return fmt.Errorf("user %s references unknown profile %s", username, ru.ProfileID)
		}

		users[username] = &UserProfile{
			Username:  username,
			ProfileID: ru.ProfileID,
		}
	}

	logs.Log(fmt.Sprintf("[AUTHZ] loaded %d users", len(users)))
	return nil
}
