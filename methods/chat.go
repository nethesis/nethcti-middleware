/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package methods

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/nethesis/nethcti-middleware/configuration"
)

// ChatInfoHandler returns a well-known JSON object for chat/Matrix configuration
// If NETHVOICE_MATRIX_BASE_URL is set, returns it as {"matrix": {"base_url": "..."}}
// If the "users" query parameter is provided, also includes a list of chat users with their extensions
// Returns an object with "matrix" and optionally "users" keys
func ChatInfoHandler(c *gin.Context) {
	var response map[string]interface{}
	response = make(map[string]interface{})

	// Add matrix configuration if available
	if configuration.Config.MatrixBaseURL != "" {
		response["matrix"] = map[string]interface{}{
			"base_url":     configuration.Config.MatrixBaseURL,
			"acrobits_url": configuration.Config.MatrixBaseURL + "/m2a",
		}
	}

	// Get all chat users with their extensions only if the users parameter is provided
	if c.Query("users") != "" {
		chatUsers, err := GetAllChatUsers()
		if err != nil {
			// Log error but don't fail the request - return what we have
		} else {
			response["users"] = chatUsers
		}
	}

	c.JSON(http.StatusOK, response)
}
