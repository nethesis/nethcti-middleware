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

	"github.com/gin-gonic/gin"
	jwtv5 "github.com/golang-jwt/jwt/v5"

	"github.com/nethesis/nethcti-middleware/configuration"
	"github.com/nethesis/nethcti-middleware/models"
	"github.com/nethesis/nethcti-middleware/store"
)

func TestWatchCallSummary_StartsUserScopedWatch(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store.UserSessionInit()
	store.UserSessions["alice"] = &models.UserSession{Username: "alice", NethCTIToken: "token"}

	configuration.Config.SatellitePgSQLHost = "test"
	configuration.Config.SatellitePgSQLPort = "5432"
	configuration.Config.SatellitePgSQLDB = "test"
	configuration.Config.SatellitePgSQLUser = "test"

	originalGetUserInfo := getUserInfoFunc
	originalCheck := checkUserParticipationFunc
	originalStartWatch := startSummaryWatchFunc
	defer func() {
		getUserInfoFunc = originalGetUserInfo
		checkUserParticipationFunc = originalCheck
		startSummaryWatchFunc = originalStartWatch
	}()

	getUserInfoFunc = func(string) (*UserInfo, error) {
		return &UserInfo{PhoneNumbers: []string{"100"}}, nil
	}
	checkUserParticipationFunc = func(string, []string) (bool, error) {
		return true, nil
	}

	var gotUniqueID, gotUsername string
	startSummaryWatchFunc = func(uniqueID, username string) bool {
		gotUniqueID = uniqueID
		gotUsername = username
		return true
	}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("JWT_PAYLOAD", jwtv5.MapClaims{"id": "alice"})
		c.Next()
	})
	router.POST("/summary/watch", WatchCallSummary)

	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{"uniqueid": "abc123"})
	req, _ := http.NewRequest("POST", "/summary/watch", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202 accepted, got %d: %s", w.Code, w.Body.String())
	}
	var response map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if response["data"] != nil {
		t.Fatalf("expected no response data, got %#v", response["data"])
	}
	if gotUniqueID != "abc123" {
		t.Fatalf("unexpected watched uniqueid: %s", gotUniqueID)
	}
	if gotUsername != "alice" {
		t.Fatalf("unexpected watched username: %s", gotUsername)
	}
}

func TestWatchCallSummary_RejectsUserOutsideCall(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store.UserSessionInit()
	store.UserSessions["alice"] = &models.UserSession{Username: "alice", NethCTIToken: "token"}

	configuration.Config.SatellitePgSQLHost = "test"
	configuration.Config.SatellitePgSQLPort = "5432"
	configuration.Config.SatellitePgSQLDB = "test"
	configuration.Config.SatellitePgSQLUser = "test"

	originalGetUserInfo := getUserInfoFunc
	originalCheck := checkUserParticipationFunc
	originalStartWatch := startSummaryWatchFunc
	defer func() {
		getUserInfoFunc = originalGetUserInfo
		checkUserParticipationFunc = originalCheck
		startSummaryWatchFunc = originalStartWatch
	}()

	getUserInfoFunc = func(string) (*UserInfo, error) {
		return &UserInfo{PhoneNumbers: []string{"100"}}, nil
	}
	checkUserParticipationFunc = func(string, []string) (bool, error) {
		return false, nil
	}

	called := false
	startSummaryWatchFunc = func(uniqueID, username string) bool {
		called = true
		return true
	}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("JWT_PAYLOAD", jwtv5.MapClaims{"id": "alice"})
		c.Next()
	})
	router.POST("/summary/watch", WatchCallSummary)

	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{"uniqueid": "abc123"})
	req, _ := http.NewRequest("POST", "/summary/watch", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 forbidden, got %d: %s", w.Code, w.Body.String())
	}
	if called {
		t.Fatalf("did not expect watch to start for non participant")
	}
}

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
	originalFetch := fetchSummaryStateFunc
	defer func() {
		getUserInfoFunc = originalGetUserInfo
		checkUserParticipationFunc = originalCheck
		fetchSummaryStateFunc = originalFetch
	}()

	getUserInfoFunc = func(string) (*UserInfo, error) {
		return &UserInfo{PhoneNumbers: []string{"100"}}, nil
	}
	checkUserParticipationFunc = func(string, []string) (bool, error) {
		return true, nil
	}
	fetchSummaryStateFunc = func(string) (string, bool, bool, bool, error) {
		return "", false, false, false, nil
	}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("JWT_PAYLOAD", jwtv5.MapClaims{"id": "alice"})
		c.Next()
	})
	router.HEAD("/summary/:uniqueid", CheckSummaryByUniqueID)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("HEAD", "/summary/abc123", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 not found, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCheckSummaryByUniqueID_ReturnsNoContentWhenSummaryIsStillProcessing(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store.UserSessionInit()
	store.UserSessions["alice"] = &models.UserSession{Username: "alice", NethCTIToken: "token"}

	configuration.Config.SatellitePgSQLHost = "test"
	configuration.Config.SatellitePgSQLPort = "5432"
	configuration.Config.SatellitePgSQLDB = "test"
	configuration.Config.SatellitePgSQLUser = "test"

	originalGetUserInfo := getUserInfoFunc
	originalCheck := checkUserParticipationFunc
	originalFetch := fetchSummaryStateFunc
	defer func() {
		getUserInfoFunc = originalGetUserInfo
		checkUserParticipationFunc = originalCheck
		fetchSummaryStateFunc = originalFetch
	}()

	getUserInfoFunc = func(string) (*UserInfo, error) {
		return &UserInfo{PhoneNumbers: []string{"100"}}, nil
	}
	checkUserParticipationFunc = func(string, []string) (bool, error) {
		return true, nil
	}
	fetchSummaryStateFunc = func(string) (string, bool, bool, bool, error) {
		return "progress", false, false, true, nil
	}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("JWT_PAYLOAD", jwtv5.MapClaims{"id": "alice"})
		c.Next()
	})
	router.HEAD("/summary/:uniqueid", CheckSummaryByUniqueID)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("HEAD", "/summary/abc123", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204 no content while summary is still processing, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCheckSummaryByUniqueID_ReturnsNoContentWhenSummaryIsSummarizing(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store.UserSessionInit()
	store.UserSessions["alice"] = &models.UserSession{Username: "alice", NethCTIToken: "token"}

	configuration.Config.SatellitePgSQLHost = "test"
	configuration.Config.SatellitePgSQLPort = "5432"
	configuration.Config.SatellitePgSQLDB = "test"
	configuration.Config.SatellitePgSQLUser = "test"

	originalGetUserInfo := getUserInfoFunc
	originalCheck := checkUserParticipationFunc
	originalFetch := fetchSummaryStateFunc
	defer func() {
		getUserInfoFunc = originalGetUserInfo
		checkUserParticipationFunc = originalCheck
		fetchSummaryStateFunc = originalFetch
	}()

	getUserInfoFunc = func(string) (*UserInfo, error) {
		return &UserInfo{PhoneNumbers: []string{"100"}}, nil
	}
	checkUserParticipationFunc = func(string, []string) (bool, error) {
		return true, nil
	}
	fetchSummaryStateFunc = func(string) (string, bool, bool, bool, error) {
		return "summarizing", false, true, true, nil
	}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("JWT_PAYLOAD", jwtv5.MapClaims{"id": "alice"})
		c.Next()
	})
	router.HEAD("/summary/:uniqueid", CheckSummaryByUniqueID)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("HEAD", "/summary/abc123", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204 no content while summary is summarizing, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCheckSummaryByUniqueID_ReturnsOKWhenSummaryExists(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store.UserSessionInit()
	store.UserSessions["alice"] = &models.UserSession{Username: "alice", NethCTIToken: "token"}

	configuration.Config.SatellitePgSQLHost = "test"
	configuration.Config.SatellitePgSQLPort = "5432"
	configuration.Config.SatellitePgSQLDB = "test"
	configuration.Config.SatellitePgSQLUser = "test"

	originalGetUserInfo := getUserInfoFunc
	originalCheck := checkUserParticipationFunc
	originalFetch := fetchSummaryStateFunc
	defer func() {
		getUserInfoFunc = originalGetUserInfo
		checkUserParticipationFunc = originalCheck
		fetchSummaryStateFunc = originalFetch
	}()

	getUserInfoFunc = func(string) (*UserInfo, error) {
		return &UserInfo{PhoneNumbers: []string{"100"}}, nil
	}
	checkUserParticipationFunc = func(string, []string) (bool, error) {
		return true, nil
	}
	fetchSummaryStateFunc = func(string) (string, bool, bool, bool, error) {
		return "done", true, true, true, nil
	}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("JWT_PAYLOAD", jwtv5.MapClaims{"id": "alice"})
		c.Next()
	})
	router.HEAD("/summary/:uniqueid", CheckSummaryByUniqueID)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("HEAD", "/summary/abc123", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 ok when summary exists, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCheckSummaryByUniqueID_ReturnsNotFoundWhenProcessingCompletedWithoutSummary(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store.UserSessionInit()
	store.UserSessions["alice"] = &models.UserSession{Username: "alice", NethCTIToken: "token"}

	configuration.Config.SatellitePgSQLHost = "test"
	configuration.Config.SatellitePgSQLPort = "5432"
	configuration.Config.SatellitePgSQLDB = "test"
	configuration.Config.SatellitePgSQLUser = "test"

	originalGetUserInfo := getUserInfoFunc
	originalCheck := checkUserParticipationFunc
	originalFetch := fetchSummaryStateFunc
	defer func() {
		getUserInfoFunc = originalGetUserInfo
		checkUserParticipationFunc = originalCheck
		fetchSummaryStateFunc = originalFetch
	}()

	getUserInfoFunc = func(string) (*UserInfo, error) {
		return &UserInfo{PhoneNumbers: []string{"100"}}, nil
	}
	checkUserParticipationFunc = func(string, []string) (bool, error) {
		return true, nil
	}
	fetchSummaryStateFunc = func(string) (string, bool, bool, bool, error) {
		return "done", false, false, true, nil
	}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("JWT_PAYLOAD", jwtv5.MapClaims{"id": "alice"})
		c.Next()
	})
	router.HEAD("/summary/:uniqueid", CheckSummaryByUniqueID)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("HEAD", "/summary/abc123", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 not found when processing completed without summary, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCheckSummaryByUniqueID_ReturnsNotFoundWhenSummaryFailed(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store.UserSessionInit()
	store.UserSessions["alice"] = &models.UserSession{Username: "alice", NethCTIToken: "token"}

	configuration.Config.SatellitePgSQLHost = "test"
	configuration.Config.SatellitePgSQLPort = "5432"
	configuration.Config.SatellitePgSQLDB = "test"
	configuration.Config.SatellitePgSQLUser = "test"

	originalGetUserInfo := getUserInfoFunc
	originalCheck := checkUserParticipationFunc
	originalFetch := fetchSummaryStateFunc
	defer func() {
		getUserInfoFunc = originalGetUserInfo
		checkUserParticipationFunc = originalCheck
		fetchSummaryStateFunc = originalFetch
	}()

	getUserInfoFunc = func(string) (*UserInfo, error) {
		return &UserInfo{PhoneNumbers: []string{"100"}}, nil
	}
	checkUserParticipationFunc = func(string, []string) (bool, error) {
		return true, nil
	}
	fetchSummaryStateFunc = func(string) (string, bool, bool, bool, error) {
		return "failed", false, false, true, nil
	}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("JWT_PAYLOAD", jwtv5.MapClaims{"id": "alice"})
		c.Next()
	})
	router.HEAD("/summary/:uniqueid", CheckSummaryByUniqueID)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("HEAD", "/summary/abc123", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 not found when summary processing failed, got %d: %s", w.Code, w.Body.String())
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

	originalGetUserInfo := getUserInfoFunc
	originalCheck := checkUserParticipationFunc
	originalFetchList := fetchSummaryListFunc
	defer func() {
		getUserInfoFunc = originalGetUserInfo
		checkUserParticipationFunc = originalCheck
		fetchSummaryListFunc = originalFetchList
	}()

	getUserInfoFunc = func(string) (*UserInfo, error) {
		return &UserInfo{PhoneNumbers: []string{"100"}}, nil
	}
	checkUserParticipationFunc = func(string, []string) (bool, error) {
		return true, nil
	}
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
		c.Set("JWT_PAYLOAD", jwtv5.MapClaims{"id": "alice"})
		c.Next()
	})
	router.POST("/summary/statuses", ListSummaryStatus)

	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string][]string{"uniqueids": {"abc123"}})
	req, _ := http.NewRequest("POST", "/summary/statuses", bytes.NewReader(body))
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

	originalGetUserInfo := getUserInfoFunc
	originalCheck := checkUserParticipationFunc
	originalFetchList := fetchSummaryListFunc
	defer func() {
		getUserInfoFunc = originalGetUserInfo
		checkUserParticipationFunc = originalCheck
		fetchSummaryListFunc = originalFetchList
	}()

	getUserInfoFunc = func(string) (*UserInfo, error) {
		return &UserInfo{PhoneNumbers: []string{"100"}}, nil
	}
	checkUserParticipationFunc = func(string, []string) (bool, error) {
		return true, nil
	}
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
		c.Set("JWT_PAYLOAD", jwtv5.MapClaims{"id": "alice"})
		c.Next()
	})
	router.POST("/summary/statuses", ListSummaryStatus)

	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string][]string{"uniqueids": {"abc123", "missing-1"}})
	req, _ := http.NewRequest("POST", "/summary/statuses", bytes.NewReader(body))
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

func TestListSummaryStatus_FiltersCallsOutsideUserParticipation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store.UserSessionInit()
	store.UserSessions["alice"] = &models.UserSession{Username: "alice", NethCTIToken: "token"}

	configuration.Config.SatellitePgSQLHost = "test"
	configuration.Config.SatellitePgSQLPort = "5432"
	configuration.Config.SatellitePgSQLDB = "test"
	configuration.Config.SatellitePgSQLUser = "test"

	originalGetUserInfo := getUserInfoFunc
	originalCheck := checkUserParticipationFunc
	originalFetchList := fetchSummaryListFunc
	defer func() {
		getUserInfoFunc = originalGetUserInfo
		checkUserParticipationFunc = originalCheck
		fetchSummaryListFunc = originalFetchList
	}()

	getUserInfoFunc = func(string) (*UserInfo, error) {
		return &UserInfo{PhoneNumbers: []string{"100"}}, nil
	}
	checkUserParticipationFunc = func(uniqueID string, phoneNumbers []string) (bool, error) {
		return uniqueID == "abc123", nil
	}

	var fetchedUniqueIDs []string
	fetchSummaryListFunc = func(uniqueIDs []string) ([]SummaryListItem, error) {
		fetchedUniqueIDs = append([]string{}, uniqueIDs...)
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
		c.Set("JWT_PAYLOAD", jwtv5.MapClaims{"id": "alice"})
		c.Next()
	})
	router.POST("/summary/statuses", ListSummaryStatus)

	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string][]string{"uniqueids": {"abc123", "switchboard-1"}})
	req, _ := http.NewRequest("POST", "/summary/statuses", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 ok, got %d: %s", w.Code, w.Body.String())
	}
	if len(fetchedUniqueIDs) != 1 || fetchedUniqueIDs[0] != "abc123" {
		t.Fatalf("expected fetch only for authorized uniqueids, got %v", fetchedUniqueIDs)
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
	if first["has_summary"] != true {
		t.Fatalf("expected summary details for authorized item, got %v", first["has_summary"])
	}

	second := response.Data[1]
	if second["uniqueid"] != "switchboard-1" {
		t.Fatalf("unexpected second uniqueid: %v", second["uniqueid"])
	}
	if second["error"] != "not_found" {
		t.Fatalf("expected not_found for unauthorized item, got %v", second["error"])
	}
	if _, ok := second["has_summary"]; ok {
		t.Fatalf("did not expect summary details for unauthorized item")
	}
}
