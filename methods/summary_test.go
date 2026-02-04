/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package methods

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"

	"github.com/nethesis/nethcti-middleware/configuration"
	"github.com/nethesis/nethcti-middleware/models"
	"github.com/nethesis/nethcti-middleware/store"
)

func TestCheckSummaryByUniqueID_NotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store.UserSessionInit()
	store.UserSessions["alice"] = &models.UserSession{Username: "alice", NethCTIToken: "token"}

	configuration.Config.SatellitePgSQLHost = "test"
	configuration.Config.SatellitePgSQLPort = "5432"
	configuration.Config.SatellitePgSQLDB = "test"
	configuration.Config.SatellitePgSQLUser = "test"

	originalGetUserInfo := getUserInfoFunc
	originalCheck := checkUserParticipationFunc
	originalFetch := fetchSummaryFunc
	defer func() {
		getUserInfoFunc = originalGetUserInfo
		checkUserParticipationFunc = originalCheck
		fetchSummaryFunc = originalFetch
	}()

	getUserInfoFunc = func(string) (*UserInfo, error) {
		return &UserInfo{PhoneNumbers: []string{"100"}}, nil
	}
	checkUserParticipationFunc = func(string, []string) (bool, error) {
		return true, nil
	}
	fetchSummaryFunc = func(string) (string, bool, error) {
		return "", false, nil
	}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("JWT_PAYLOAD", jwt.MapClaims{"id": "alice"})
		c.Next()
	})
	router.GET("/summary/check/:uniqueid", CheckSummaryByUniqueID)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/summary/check/abc123", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 not found, got %d: %s", w.Code, w.Body.String())
	}
}

func TestListSummaryStatus_Succeeds(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store.UserSessionInit()
	store.UserSessions["alice"] = &models.UserSession{Username: "alice", NethCTIToken: "token"}

	configuration.Config.SatellitePgSQLHost = "test"
	configuration.Config.SatellitePgSQLPort = "5432"
	configuration.Config.SatellitePgSQLDB = "test"
	configuration.Config.SatellitePgSQLUser = "test"

	originalFetchList := fetchSummaryListFunc
	defer func() {
		fetchSummaryListFunc = originalFetchList
	}()

	fetchSummaryListFunc = func([]string) ([]SummaryListItem, error) {
		updatedAt := time.Now()
		return []SummaryListItem{
			{
				UniqueID:         "abc123",
				State:            "done",
				HasTranscription: true,
				HasSummary:       true,
				UpdatedAt:        &updatedAt,
			},
		}, nil
	}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("JWT_PAYLOAD", jwt.MapClaims{"id": "alice"})
		c.Next()
	})
	router.POST("/summary/check/list", ListSummaryStatus)

	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string][]string{"uniqueids": {"abc123"}})
	req, _ := http.NewRequest("POST", "/summary/check/list", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 ok, got %d: %s", w.Code, w.Body.String())
	}

	var response struct {
		Data []SummaryListItem `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(response.Data) != 1 {
		t.Fatalf("expected 1 item, got %d", len(response.Data))
	}
}

func TestListSummaryStatus_MixedResults(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store.UserSessionInit()
	store.UserSessions["alice"] = &models.UserSession{Username: "alice", NethCTIToken: "token"}

	configuration.Config.SatellitePgSQLHost = "test"
	configuration.Config.SatellitePgSQLPort = "5432"
	configuration.Config.SatellitePgSQLDB = "test"
	configuration.Config.SatellitePgSQLUser = "test"

	originalFetchList := fetchSummaryListFunc
	defer func() {
		fetchSummaryListFunc = originalFetchList
	}()

	fetchSummaryListFunc = func([]string) ([]SummaryListItem, error) {
		updatedAt := time.Now()
		return []SummaryListItem{
			{
				UniqueID:         "abc123",
				State:            "done",
				HasTranscription: true,
				HasSummary:       true,
				UpdatedAt:        &updatedAt,
			},
		}, nil
	}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("JWT_PAYLOAD", jwt.MapClaims{"id": "alice"})
		c.Next()
	})
	router.POST("/summary/check/list", ListSummaryStatus)

	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string][]string{"uniqueids": {"abc123", "missing-1"}})
	req, _ := http.NewRequest("POST", "/summary/check/list", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 ok, got %d: %s", w.Code, w.Body.String())
	}

	var response struct {
		Data []map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(response.Data) != 2 {
		t.Fatalf("expected 2 items, got %d", len(response.Data))
	}

	first := response.Data[0]
	if first["uniqueid"] != "abc123" {
		t.Fatalf("unexpected first uniqueid: %v", first["uniqueid"])
	}
	if _, ok := first["state"]; !ok {
		t.Fatalf("expected state in found item")
	}

	second := response.Data[1]
	if second["uniqueid"] != "missing-1" {
		t.Fatalf("unexpected second uniqueid: %v", second["uniqueid"])
	}
	if second["error"] != "not_found" {
		t.Fatalf("expected not_found error, got %v", second["error"])
	}
	if _, ok := second["state"]; ok {
		t.Fatalf("did not expect state for missing item")
	}
}
