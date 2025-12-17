/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package methods

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/nethesis/nethcti-middleware/configuration"
	"github.com/nethesis/nethcti-middleware/logs"
	"github.com/nethesis/nethcti-middleware/store"
)

// Extension represents a phone extension (only ID is used)
type Extension struct {
	ID string `json:"id"`
}

// Endpoints represents endpoint types (only extension and mainextension are used)
type Endpoints struct {
	Extension     []Extension `json:"extension"`
	MainExtension []Extension `json:"mainextension"`
}

// UserInfo represents user information from the API (only fields we need)
type UserInfo struct {
	Name      string    `json:"name"`
	Username  string    `json:"username"`
	Endpoints Endpoints `json:"endpoints"`

	// Computed fields for easier access
	DisplayName  string   `json:"-"`
	PhoneNumbers []string `json:"-"`
}

// ChatUser represents user information for chat purposes
type ChatUser struct {
	UserName      string   `json:"user_name"`
	MainExtension string   `json:"main_extension"`
	SubExtensions []string `json:"sub_extensions"`
}

// GetUserInfo retrieves user information from V1 API using the provided token
func GetUserInfo(nethCTIToken string) (*UserInfo, error) {
	// Build the URL for user info endpoint
	url := fmt.Sprintf("%s://%s%s/user/me",
		configuration.Config.V1Protocol,
		configuration.Config.V1ApiEndpoint,
		configuration.Config.V1ApiPath)

	// Create the request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		logs.Log("[ERROR][USER] Failed to create user info request: " + err.Error())
		return nil, err
	}

	// Add authorization header
	req.Header.Set("Authorization", nethCTIToken)
	req.Header.Set("Content-Type", "application/json")

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: time.Second * 10,
	}

	// Make the request
	resp, err := client.Do(req)
	if err != nil {
		logs.Log("[ERROR][USER] Failed to get user info: " + err.Error())
		return nil, err
	}
	defer resp.Body.Close()

	// Check if request was successful
	if resp.StatusCode != http.StatusOK {
		logs.Log(fmt.Sprintf("[ERROR][USER] User info request failed with status: %d", resp.StatusCode))
		return nil, fmt.Errorf("user info request failed with status: %d", resp.StatusCode)
	}

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logs.Log("[ERROR][USER] Failed to read user info response: " + err.Error())
		return nil, err
	}

	// Parse the JSON response
	var userInfo UserInfo
	err = json.Unmarshal(body, &userInfo)
	if err != nil {
		logs.Log("[ERROR][USER] Failed to parse user info JSON: " + err.Error())
		return nil, err
	}

	// Populate computed fields
	userInfo.DisplayName = userInfo.Name
	userInfo.PhoneNumbers = []string{}

	// Extract all extension IDs from endpoints.extension
	for _, extension := range userInfo.Endpoints.Extension {
		userInfo.PhoneNumbers = append(userInfo.PhoneNumbers, extension.ID)
	}

	// Also extract main extension IDs if different
	for _, mainExt := range userInfo.Endpoints.MainExtension {
		// Only add if not already in the list
		found := false
		for _, existing := range userInfo.PhoneNumbers {
			if existing == mainExt.ID {
				found = true
				break
			}
		}
		if !found {
			userInfo.PhoneNumbers = append(userInfo.PhoneNumbers, mainExt.ID)
		}
	}

	logs.Log(fmt.Sprintf("[INFO][USER] Retrieved user info for: %s (%s) with extensions: %v",
		userInfo.Username, userInfo.DisplayName, userInfo.PhoneNumbers))

	return &userInfo, nil
}

// GetAllChatUsers retrieves all users with the nethvoice_cti.chat capability
// Returns a list of chat users with their extensions from the user profiles
func GetAllChatUsers() ([]ChatUser, error) {
	// Get chat users from store based on capabilities
	chatUsersMap, err := store.GetChatUsers()
	if err != nil {
		logs.Log("[ERROR][USER] Failed to get chat users: " + err.Error())
		return nil, err
	}

	// Convert to ChatUser format
	var chatUsers []ChatUser
	for _, userProfile := range chatUsersMap {
		// Get sub extensions (all extensions except main)
		var subExts []string
		for _, ext := range userProfile.Extensions {
			if ext != userProfile.MainExtension {
				subExts = append(subExts, ext)
			}
		}

		chatUsers = append(chatUsers, ChatUser{
			UserName:      userProfile.Username,
			MainExtension: userProfile.MainExtension,
			SubExtensions: subExts,
		})
	}

	logs.Log(fmt.Sprintf("[INFO][USER] Retrieved %d chat users from profiles", len(chatUsers)))

	return chatUsers, nil
}
