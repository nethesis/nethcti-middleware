/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package methods

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"

	"github.com/nethesis/nethcti-middleware/configuration"
	"github.com/nethesis/nethcti-middleware/logs"
)

// TestChatInfoHandlerWithMatrixURL tests the handler when MatrixBaseURL is set
func TestChatInfoHandlerWithMatrixURL(t *testing.T) {
	logs.Init("nethcti-test")
	gin.SetMode(gin.TestMode)

	// Save original config
	originalMatrixBaseURL := configuration.Config.MatrixBaseURL

	// Set MatrixBaseURL
	configuration.Config.MatrixBaseURL = "https://matrix.example.com"

	// Create router and route
	router := gin.New()
	router.GET("/chat", ChatInfoHandler)

	// Create request
	req, err := http.NewRequest("GET", "/chat", nil)
	assert.NoError(t, err)

	// Perform request
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)

	// Check structure
	matrix, ok := response["matrix"]
	assert.True(t, ok, "matrix key should exist")

	matrixMap, ok := matrix.(map[string]interface{})
	assert.True(t, ok, "matrix should be a map")

	baseURL, ok := matrixMap["base_url"]
	assert.True(t, ok, "base_url key should exist in matrix")
	assert.Equal(t, "https://matrix.example.com", baseURL)

	acrobitsURL, ok := matrixMap["acrobits_url"]
	assert.True(t, ok, "acrobits_url key should exist in matrix")
	assert.Equal(t, "https://matrix.example.com/m2a", acrobitsURL)

	// Restore original config
	configuration.Config.MatrixBaseURL = originalMatrixBaseURL
}

// TestChatInfoHandlerWithoutMatrixURL tests the handler when MatrixBaseURL is empty
func TestChatInfoHandlerWithoutMatrixURL(t *testing.T) {
	logs.Init("nethcti-test")
	gin.SetMode(gin.TestMode)

	// Save original config
	originalMatrixBaseURL := configuration.Config.MatrixBaseURL

	// Clear MatrixBaseURL
	configuration.Config.MatrixBaseURL = ""

	// Create router and route
	router := gin.New()
	router.GET("/chat", ChatInfoHandler)

	// Create request
	req, err := http.NewRequest("GET", "/chat", nil)
	assert.NoError(t, err)

	// Perform request
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)

	// Should return empty object
	assert.Equal(t, 0, len(response), "response should be an empty object")

	// Restore original config
	configuration.Config.MatrixBaseURL = originalMatrixBaseURL
}

// TestChatInfoHandlerWithUsersParameter tests the handler with users query parameter
func TestChatInfoHandlerWithUsersParameter(t *testing.T) {
	logs.Init("nethcti-test")
	gin.SetMode(gin.TestMode)

	// Save original config
	originalMatrixBaseURL := configuration.Config.MatrixBaseURL

	// Set MatrixBaseURL
	configuration.Config.MatrixBaseURL = "https://matrix.example.com"

	// Create router and route
	router := gin.New()
	router.GET("/chat", ChatInfoHandler)

	// Create request with users parameter
	req, err := http.NewRequest("GET", "/chat?users=1", nil)
	assert.NoError(t, err)

	// Perform request
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)

	// Check matrix structure exists
	matrix, ok := response["matrix"]
	assert.True(t, ok, "matrix key should exist")

	matrixMap, ok := matrix.(map[string]interface{})
	assert.True(t, ok, "matrix should be a map")

	baseURL, ok := matrixMap["base_url"]
	assert.True(t, ok, "base_url key should exist in matrix")
	assert.Equal(t, "https://matrix.example.com", baseURL)

	// Users field may or may not exist depending on API availability, but no error should occur
	// The handler gracefully handles API failures

	// Restore original config
	configuration.Config.MatrixBaseURL = originalMatrixBaseURL
}

// TestChatInfoHandlerWithoutUsersParameter tests the handler without users query parameter
func TestChatInfoHandlerWithoutUsersParameter(t *testing.T) {
	logs.Init("nethcti-test")
	gin.SetMode(gin.TestMode)

	// Save original config
	originalMatrixBaseURL := configuration.Config.MatrixBaseURL

	// Set MatrixBaseURL
	configuration.Config.MatrixBaseURL = "https://matrix.example.com"

	// Create router and route
	router := gin.New()
	router.GET("/chat", ChatInfoHandler)

	// Create request WITHOUT users parameter
	req, err := http.NewRequest("GET", "/chat", nil)
	assert.NoError(t, err)

	// Perform request
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)

	// Check matrix structure exists
	matrix, ok := response["matrix"]
	assert.True(t, ok, "matrix key should exist")

	_, ok = matrix.(map[string]interface{})
	assert.True(t, ok, "matrix should be a map")

	// Users field should NOT exist when parameter is not provided
	_, usersExists := response["users"]
	assert.False(t, usersExists, "users key should NOT exist without users parameter")

	// Restore original config
	configuration.Config.MatrixBaseURL = originalMatrixBaseURL
}
