/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package store

import (
	_ "embed"
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

// UserProfile links a username to a profile with extension information
type UserProfile struct {
	Username      string
	ProfileID     string
	MainExtension string
	Extensions    []string
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

type rawEndpoint struct {
	Type     string `json:"type"`
	User     string `json:"user"`
	Password string `json:"password"`
}

type rawEndpoints struct {
	MainExtension map[string]rawEndpoint `json:"mainextension"`
	Extension     map[string]rawEndpoint `json:"extension"`
}

type rawUser struct {
	Name      string       `json:"name"`
	ProfileID string       `json:"profile_id"`
	Endpoints rawEndpoints `json:"endpoints"`
}

var (
	profiles         map[string]*ProfileData
	users            map[string]*UserProfile
	profileMutex     sync.RWMutex
	profilesFilePath string
	usersFilePath    string
)

//go:embed default_profiles.json
var defaultProfilesJSON []byte

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

	// Store file paths for reload functionality
	profilesFilePath = profAbs
	usersFilePath = usersAbs

	// Load profiles using temp function
	newProfiles, err := loadProfiles(profAbs)
	if err != nil {
		return err
	}

	// Load users using temp function
	newUsers, err := loadUsers(usersAbs, newProfiles)
	if err != nil {
		return err
	}

	// Update global state
	profileMutex.Lock()
	profiles = newProfiles
	users = newUsers
	profileMutex.Unlock()

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

// GetChatUsers returns a list of users that have the nethvoice_cti.chat capability
func GetChatUsers() (map[string]*UserProfile, error) {
	profileMutex.RLock()
	defer profileMutex.RUnlock()

	chatUsers := make(map[string]*UserProfile)
	for username, userProfile := range users {
		profile, ok := profiles[userProfile.ProfileID]
		if !ok {
			// Skip users with invalid profiles
			continue
		}

		// Check if user has chat capability
		if profile.Capabilities["nethvoice_cti.chat"] {
			chatUsers[username] = userProfile
		}
	}

	return chatUsers, nil
}

// ReloadProfiles reloads profiles and users from JSON files, keeping old data on failure
func ReloadProfiles() error {
	// Load new profiles and users into temporary variables
	newProfiles, profilesErr := loadProfiles(profilesFilePath)

	// If profiles failed to load, attempt to reload users against the currently loaded profiles
	var usersTarget map[string]*ProfileData
	if profilesErr != nil {
		profileMutex.RLock()
		usersTarget = profiles
		profileMutex.RUnlock()
	} else {
		usersTarget = newProfiles
	}

	newUsers, usersErr := loadUsers(usersFilePath, usersTarget)

	// If both failed, return error and keep old data in memory
	if profilesErr != nil && usersErr != nil {
		logs.Log(fmt.Sprintf("[ERROR][AUTH] Failed to reload profiles: %v", profilesErr))
		logs.Log(fmt.Sprintf("[ERROR][AUTH] Failed to reload users: %v", usersErr))
		return fmt.Errorf("reload failed for both profiles and users")
	}

	// Update profiles if load succeeded, otherwise keep old data
	if profilesErr != nil {
		logs.Log(fmt.Sprintf("[WARNING][AUTH] Failed to reload profiles (keeping previous data): %v", profilesErr))
	} else {
		profileMutex.Lock()
		profiles = newProfiles
		profileMutex.Unlock()
	}

	// Update users if load succeeded, otherwise keep old data
	if usersErr != nil {
		logs.Log(fmt.Sprintf("[WARNING][AUTH] Failed to reload users (keeping previous data): %v", usersErr))
	} else {
		profileMutex.Lock()
		users = newUsers
		profileMutex.Unlock()
	}

	logs.Log("[INFO][AUTH] Profile reload completed successfully")
	return nil
}

// loadProfiles loads profiles into a temporary map without modifying global state
func loadProfiles(path string) (map[string]*ProfileData, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		// If the provided profiles file cannot be read, fall back to the embedded default
		logs.Log(fmt.Sprintf("[WARNING][AUTH] Could not read profiles file %s: %v; using embedded defaults", path, err))
		data = defaultProfilesJSON
	}

	raw := make(map[string]*rawProfile)
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse profiles: %w", err)
	}

	result := make(map[string]*ProfileData)
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
			capMap[macroName] = macro.Value
			for _, permission := range macro.Permissions {
				key := fmt.Sprintf("%s.%s", macroName, permission.Name)
				capMap[key] = permission.Value
			}
		}

		result[profID] = &ProfileData{
			ID:           profID,
			Name:         rp.Name,
			Capabilities: capMap,
		}
	}

	logs.Log(fmt.Sprintf("[INFO][AUTH] loaded %d profiles", len(result)))
	return result, nil
}

// loadUsers loads users into a temporary map without modifying global state
func loadUsers(path string, profilesMap map[string]*ProfileData) (map[string]*UserProfile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read users: %w", err)
	}

	raw := make(map[string]*rawUser)
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse users: %w", err)
	}

	result := make(map[string]*UserProfile)
	for username, ru := range raw {
		if ru.ProfileID == "" {
			return nil, fmt.Errorf("user %s missing profile reference", username)
		}

		if _, ok := profilesMap[ru.ProfileID]; !ok {
			return nil, fmt.Errorf("user %s references unknown profile %s", username, ru.ProfileID)
		}

		// Extract main extension
		var mainExt string
		for extID := range ru.Endpoints.MainExtension {
			mainExt = extID
			break // Take first one
		}

		// Extract extensions
		exts := make([]string, 0)
		for extID := range ru.Endpoints.Extension {
			exts = append(exts, extID)
		}

		result[username] = &UserProfile{
			Username:      username,
			ProfileID:     ru.ProfileID,
			MainExtension: mainExt,
			Extensions:    exts,
		}
	}

	logs.Log(fmt.Sprintf("[INFO][AUTH] loaded %d users", len(result)))
	return result, nil
}
