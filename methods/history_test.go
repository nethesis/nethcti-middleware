/*
 * Copyright (C) 2026 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package methods

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/nethesis/nethcti-middleware/configuration"
	"github.com/nethesis/nethcti-middleware/models"
	"github.com/nethesis/nethcti-middleware/store"
)

func TestGetFilteredHistory_ReturnsServiceUnavailableWhenTranscriptsTableIsMissing(t *testing.T) {
	router, cleanup := setupHistoryArtifactTest(t, func([]string) ([]SummaryListItem, error) {
		return nil, &pgconn.PgError{Code: "42P01", Message: `relation "transcripts" does not exist`}
	})
	defer cleanup()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/history/calls?callType=user&username=alice&from=20260430&to=20260507&artifact=summary", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 service unavailable, got %d: %s", w.Code, w.Body.String())
	}

	var response struct {
		Message string                 `json:"message"`
		Data    map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if response.Message != "satellite database schema not initialized" {
		t.Fatalf("unexpected message: %s", response.Message)
	}
	if response.Data["missing_table"] != "transcripts" {
		t.Fatalf("unexpected missing_table: %v", response.Data["missing_table"])
	}
}

func TestGetFilteredHistory_ReturnsServiceUnavailableWhenSatelliteDBIsUnavailable(t *testing.T) {
	router, cleanup := setupHistoryArtifactTest(t, func([]string) ([]SummaryListItem, error) {
		return nil, sql.ErrConnDone
	})
	defer cleanup()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/history/calls?callType=user&username=alice&from=20260430&to=20260507&artifact=transcription", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 service unavailable, got %d: %s", w.Code, w.Body.String())
	}

	var response struct {
		Message string                 `json:"message"`
		Data    map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if response.Message != "satellite database unavailable" {
		t.Fatalf("unexpected message: %s", response.Message)
	}
	if response.Data["reason"] != "connection_unavailable" {
		t.Fatalf("unexpected reason: %v", response.Data["reason"])
	}
}

func setupHistoryArtifactTest(t *testing.T, fetchList func([]string) ([]SummaryListItem, error)) (*gin.Engine, func()) {
	t.Helper()

	gin.SetMode(gin.TestMode)
	store.UserSessionInit()
	store.UserSessions["alice"] = &models.UserSession{Username: "alice", NethCTIToken: "legacy-token"}

	legacyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"count":1,"rows":[{"linkedid":"abc123"}]}`))
	}))

	originalConfig := configuration.Config
	configuration.Config.V1Protocol = "http"
	configuration.Config.V1ApiEndpoint = strings.TrimPrefix(legacyServer.URL, "http://")
	configuration.Config.V1ApiPath = ""
	configuration.Config.SatellitePgSQLHost = "test"
	configuration.Config.SatellitePgSQLPort = "5432"
	configuration.Config.SatellitePgSQLDB = "test"
	configuration.Config.SatellitePgSQLUser = "test"

	originalGetUserInfo := getUserInfoFunc
	originalCheck := checkUserParticipationFunc
	originalFetchList := fetchSummaryListFunc

	getUserInfoFunc = func(string) (*UserInfo, error) {
		return &UserInfo{PhoneNumbers: []string{"100"}}, nil
	}
	checkUserParticipationFunc = func(string, []string) (bool, error) {
		return true, nil
	}
	fetchSummaryListFunc = fetchList

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("JWT_PAYLOAD", jwtv5.MapClaims{"id": "alice"})
		c.Next()
	})
	router.GET("/history/calls", GetFilteredHistory)

	cleanup := func() {
		legacyServer.Close()
		configuration.Config = originalConfig
		getUserInfoFunc = originalGetUserInfo
		checkUserParticipationFunc = originalCheck
		fetchSummaryListFunc = originalFetchList
	}

	return router, cleanup
}
