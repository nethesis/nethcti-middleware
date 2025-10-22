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
)

// Extension represents a phone extension
type Extension struct {
	ID          string          `json:"id"`
	Type        string          `json:"type"`
	Secret      string          `json:"secret"`
	Username    string          `json:"username"`
	Description string          `json:"description"`
	Actions     map[string]bool `json:"actions"`
}

// Endpoints represents all endpoint types
type Endpoints struct {
	Email         []interface{} `json:"email"`
	Jabber        []interface{} `json:"jabber"`
	Extension     []Extension   `json:"extension"`
	Cellphone     []interface{} `json:"cellphone"`
	Voicemail     []interface{} `json:"voicemail"`
	MainExtension []Extension   `json:"mainextension"`
}

// DefaultDevice represents the default device
type DefaultDevice struct {
	ID          string          `json:"id"`
	Type        string          `json:"type"`
	Secret      string          `json:"secret"`
	Username    string          `json:"username"`
	Description string          `json:"description"`
	Actions     map[string]bool `json:"actions"`
}

// Profile represents user profile with permissions
type Profile struct {
	ID                        string                 `json:"id"`
	Name                      string                 `json:"name"`
	MacroPermissions          map[string]interface{} `json:"macro_permissions"`
	OutboundRoutesPermissions []interface{}          `json:"outbound_routes_permissions"`
}

// Settings represents user settings
type Settings struct {
	DesktopNotifications bool   `json:"desktop_notifications"`
	OpenCcard            string `json:"open_ccard"`
	ChatNotifications    bool   `json:"chat_notifications"`
	DefaultExtension     string `json:"default_extension"`
}

// UserInfo represents complete user information from the API
type UserInfo struct {
	Name                  string        `json:"name"`
	Username              string        `json:"username"`
	MainPresence          string        `json:"mainPresence"`
	Presence              string        `json:"presence"`
	Endpoints             Endpoints     `json:"endpoints"`
	PresenceOnBusy        string        `json:"presenceOnBusy"`
	PresenceOnUnavailable string        `json:"presenceOnUnavailable"`
	RecallOnBusy          string        `json:"recallOnBusy"`
	Profile               Profile       `json:"profile"`
	DefaultDevice         DefaultDevice `json:"default_device"`
	LKHash                string        `json:"lkhash"`
	ProxyFQDN             string        `json:"proxy_fqdn"`
	Settings              Settings      `json:"settings"`

	// Computed fields for easier access
	DisplayName  string   `json:"-"`
	PhoneNumbers []string `json:"-"`
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
