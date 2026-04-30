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

func TestGetTranscriptionByUniqueID_UnauthorizedWhenNotParticipant(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store.UserSessionInit()
	store.UserSessions["alice"] = &models.UserSession{Username: "alice", NethCTIToken: "token"}

	configuration.Config.SatellitePgSQLHost = "test"
	configuration.Config.SatellitePgSQLPort = "5432"
	configuration.Config.SatellitePgSQLDB = "test"
	configuration.Config.SatellitePgSQLUser = "test"

	originalGetUserInfo := getUserInfoFunc
	originalCheck := checkUserParticipationFunc
	originalCheckByLinkedID := checkUserParticipationByLinkedIDFunc
	defer func() {
		getUserInfoFunc = originalGetUserInfo
		checkUserParticipationFunc = originalCheck
		checkUserParticipationByLinkedIDFunc = originalCheckByLinkedID
	}()

	getUserInfoFunc = func(string) (*UserInfo, error) {
		return &UserInfo{PhoneNumbers: []string{"100"}}, nil
	}
	checkUserParticipationFunc = func(string, []string) (bool, error) {
		return false, nil
	}
	checkUserParticipationByLinkedIDFunc = func(string, []string) (bool, error) {
		return false, nil
	}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("JWT_PAYLOAD", jwtv5.MapClaims{"id": "alice"})
		c.Next()
	})
	router.GET("/transcripts/:uniqueid", GetTranscriptionByUniqueID)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/transcripts/abc123", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 forbidden, got %d: %s", w.Code, w.Body.String())
	}
}

func TestGetTranscriptionByUniqueID_ReturnsExtendedData(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store.UserSessionInit()
	store.UserSessions["alice"] = &models.UserSession{Username: "alice", NethCTIToken: "token"}

	configuration.Config.SatellitePgSQLHost = "test"
	configuration.Config.SatellitePgSQLPort = "5432"
	configuration.Config.SatellitePgSQLDB = "test"
	configuration.Config.SatellitePgSQLUser = "test"

	originalGetUserInfo := getUserInfoFunc
	originalCheck := checkUserParticipationFunc
	originalFetchTranscription := fetchTranscriptionFunc
	originalFetchMeta := fetchTranscriptionMetaFunc
	defer func() {
		getUserInfoFunc = originalGetUserInfo
		checkUserParticipationFunc = originalCheck
		fetchTranscriptionFunc = originalFetchTranscription
		fetchTranscriptionMetaFunc = originalFetchMeta
	}()

	getUserInfoFunc = func(string) (*UserInfo, error) {
		return &UserInfo{PhoneNumbers: []string{"100"}}, nil
	}
	checkUserParticipationFunc = func(string, []string) (bool, error) {
		return true, nil
	}
	createdAt := time.Now()
	fetchTranscriptionFunc = func(uniqueID string) (string, *time.Time, bool, error) {
		if uniqueID != "abc123" {
			return "", nil, false, nil
		}
		return "transcription text", &createdAt, true, nil
	}
	callTimestamp := time.Now()
	fetchTranscriptionMetaFunc = func(uniqueID string) (*CallMetadata, error) {
		if uniqueID != "abc123" {
			t.Fatalf("unexpected cdr metadata lookup id: %s", uniqueID)
		}
		return &CallMetadata{
			Src:           "100",
			Dst:           "200",
			CNam:          "Alice",
			Company:       "Acme",
			DstCompany:    "Globex",
			DstCNam:       "Bob",
			CallTimestamp: &callTimestamp,
		}, nil
	}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("JWT_PAYLOAD", jwtv5.MapClaims{"id": "alice"})
		c.Next()
	})
	router.GET("/transcripts/:uniqueid", GetTranscriptionByUniqueID)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/transcripts/abc123", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 ok, got %d: %s", w.Code, w.Body.String())
	}

	var response struct {
		Data TranscriptionDrawer `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if response.Data.UniqueID != "abc123" || response.Data.Transcription != "transcription text" {
		t.Fatalf("unexpected transcription payload: %+v", response.Data)
	}
	if response.Data.Src != "100" || response.Data.CNum != "100" || response.Data.Dst != "200" {
		t.Fatalf("unexpected src/cnum/dst: %+v", response.Data)
	}
	if response.Data.CNam != "Alice" || response.Data.DstCNam != "Bob" {
		t.Fatalf("unexpected cnam fields: %+v", response.Data)
	}
	if response.Data.Company != "Acme" || response.Data.CCompany != "Acme" || response.Data.DstCompany != "Globex" {
		t.Fatalf("unexpected company fields: %+v", response.Data)
	}
	if response.Data.CallTimestamp == nil {
		t.Fatalf("expected call_timestamp to be populated: %+v", response.Data)
	}
	if response.Data.CreatedAt == nil {
		t.Fatalf("expected created_at to be populated: %+v", response.Data)
	}
}

func TestUpdateSummary_SucceedsWhenAuthorized(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store.UserSessionInit()
	store.UserSessions["alice"] = &models.UserSession{Username: "alice", NethCTIToken: "token"}

	configuration.Config.SatellitePgSQLHost = "test"
	configuration.Config.SatellitePgSQLPort = "5432"
	configuration.Config.SatellitePgSQLDB = "test"
	configuration.Config.SatellitePgSQLUser = "test"

	originalGetUserInfo := getUserInfoFunc
	originalCheck := checkUserParticipationFunc
	originalUpdate := updateSummaryFunc
	defer func() {
		getUserInfoFunc = originalGetUserInfo
		checkUserParticipationFunc = originalCheck
		updateSummaryFunc = originalUpdate
	}()

	getUserInfoFunc = func(string) (*UserInfo, error) {
		return &UserInfo{PhoneNumbers: []string{"100"}}, nil
	}
	checkUserParticipationFunc = func(string, []string) (bool, error) {
		return true, nil
	}
	var updatedUniqueID string
	var updatedSummary string
	updateSummaryFunc = func(uniqueID, summaryText string) (bool, error) {
		updatedUniqueID = uniqueID
		updatedSummary = summaryText
		return uniqueID == "abc123", nil
	}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("JWT_PAYLOAD", jwtv5.MapClaims{"id": "alice"})
		c.Next()
	})
	router.PUT("/summary/:uniqueid", UpdateSummaryByUniqueID)

	body, _ := json.Marshal(map[string]string{"summary": "test summary"})
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("PUT", "/summary/abc123", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 ok, got %d: %s", w.Code, w.Body.String())
	}
	if updatedSummary != "test summary" {
		t.Fatalf("expected summary to be updated, got %q", updatedSummary)
	}
	if updatedUniqueID != "abc123" {
		t.Fatalf("expected update to use path uniqueid, got %q", updatedUniqueID)
	}
}

func TestDeleteSummary_SucceedsWhenAuthorized(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store.UserSessionInit()
	store.UserSessions["alice"] = &models.UserSession{Username: "alice", NethCTIToken: "token"}

	configuration.Config.SatellitePgSQLHost = "test"
	configuration.Config.SatellitePgSQLPort = "5432"
	configuration.Config.SatellitePgSQLDB = "test"
	configuration.Config.SatellitePgSQLUser = "test"

	originalGetUserInfo := getUserInfoFunc
	originalCheck := checkUserParticipationFunc
	originalDelete := deleteSummaryFunc
	defer func() {
		getUserInfoFunc = originalGetUserInfo
		checkUserParticipationFunc = originalCheck
		deleteSummaryFunc = originalDelete
	}()

	getUserInfoFunc = func(string) (*UserInfo, error) {
		return &UserInfo{PhoneNumbers: []string{"100"}}, nil
	}
	checkUserParticipationFunc = func(string, []string) (bool, error) {
		return true, nil
	}
	var deletedUniqueID string
	deleteSummaryFunc = func(uniqueID string) (bool, error) {
		deletedUniqueID = uniqueID
		return uniqueID == "abc123", nil
	}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("JWT_PAYLOAD", jwtv5.MapClaims{"id": "alice"})
		c.Next()
	})
	router.DELETE("/summary/:uniqueid", DeleteSummaryByUniqueID)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("DELETE", "/summary/abc123", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 ok, got %d: %s", w.Code, w.Body.String())
	}
	if deletedUniqueID != "abc123" {
		t.Fatalf("expected delete to use path uniqueid, got %q", deletedUniqueID)
	}
}

func TestGetSummaryByUniqueID_ReturnsExtendedData(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store.UserSessionInit()
	store.UserSessions["alice"] = &models.UserSession{Username: "alice", NethCTIToken: "token"}

	configuration.Config.SatellitePgSQLHost = "test"
	configuration.Config.SatellitePgSQLPort = "5432"
	configuration.Config.SatellitePgSQLDB = "test"
	configuration.Config.SatellitePgSQLUser = "test"

	originalGetUserInfo := getUserInfoFunc
	originalCheck := checkUserParticipationFunc
	originalFetch := fetchSummaryDrawerFunc
	defer func() {
		getUserInfoFunc = originalGetUserInfo
		checkUserParticipationFunc = originalCheck
		fetchSummaryDrawerFunc = originalFetch
	}()

	getUserInfoFunc = func(string) (*UserInfo, error) {
		return &UserInfo{PhoneNumbers: []string{"100"}}, nil
	}
	checkUserParticipationFunc = func(string, []string) (bool, error) {
		return true, nil
	}
	fetchSummaryDrawerFunc = func(uniqueID string) (*SummaryDrawer, bool, error) {
		if uniqueID != "abc123" {
			return nil, false, nil
		}
		callTimestamp := time.Now()
		return &SummaryDrawer{
			UniqueID:      uniqueID,
			Summary:       "summary text",
			State:         "done",
			Src:           "100",
			Dst:           "200",
			CNam:          "Alice",
			Company:       "Acme",
			DstCompany:    "Globex",
			DstCNam:       "Bob",
			CallTimestamp: &callTimestamp,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		}, true, nil
	}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("JWT_PAYLOAD", jwtv5.MapClaims{"id": "alice"})
		c.Next()
	})
	router.GET("/summary/:uniqueid", GetSummaryByUniqueID)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/summary/abc123", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 ok, got %d: %s", w.Code, w.Body.String())
	}

	var response struct {
		Data SummaryDrawer `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if response.Data.UniqueID != "abc123" {
		t.Fatalf("expected response uniqueid to stay aligned with the API identifier, got %+v", response.Data)
	}
	if response.Data.Src != "100" || response.Data.Dst != "200" {
		t.Fatalf("unexpected src/dst: %+v", response.Data)
	}
	if response.Data.CNam != "Alice" || response.Data.DstCNam != "Bob" {
		t.Fatalf("unexpected cnam fields: %+v", response.Data)
	}
	if response.Data.Company != "Acme" || response.Data.DstCompany != "Globex" {
		t.Fatalf("unexpected company fields: %+v", response.Data)
	}
	if response.Data.CallTimestamp == nil {
		t.Fatalf("expected call_timestamp to be populated: %+v", response.Data)
	}
}
func TestGetTranscriptionByUniqueID_CanonicalRowWithDuplicateUniqueIDs(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store.UserSessionInit()
	store.UserSessions["alice"] = &models.UserSession{Username: "alice", NethCTIToken: "token"}

	configuration.Config.SatellitePgSQLHost = "test"
	configuration.Config.SatellitePgSQLPort = "5432"
	configuration.Config.SatellitePgSQLDB = "test"
	configuration.Config.SatellitePgSQLUser = "test"

	originalGetUserInfo := getUserInfoFunc
	originalCheck := checkUserParticipationFunc
	originalFetchTranscription := fetchTranscriptionFunc
	originalFetchMeta := fetchTranscriptionMetaFunc
	defer func() {
		getUserInfoFunc = originalGetUserInfo
		checkUserParticipationFunc = originalCheck
		fetchTranscriptionFunc = originalFetchTranscription
		fetchTranscriptionMetaFunc = originalFetchMeta
	}()

	getUserInfoFunc = func(string) (*UserInfo, error) {
		return &UserInfo{PhoneNumbers: []string{"100"}}, nil
	}
	checkUserParticipationFunc = func(string, []string) (bool, error) {
		return true, nil
	}

	// Simulate two satellite rows for the same uniqueid; the DB function returns the latest one.
	latestCreatedAt := time.Now()
	fetchTranscriptionFunc = func(uniqueID string) (string, *time.Time, bool, error) {
		// The DB function applies ORDER BY updated_at DESC, id DESC LIMIT 1,
		// so only the latest row is returned here.
		return "latest fragment transcript", &latestCreatedAt, true, nil
	}
	fetchTranscriptionMetaFunc = func(string) (*CallMetadata, error) {
		return &CallMetadata{Src: "100", Dst: "200"}, nil
	}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("JWT_PAYLOAD", jwtv5.MapClaims{"id": "alice"})
		c.Next()
	})
	router.GET("/transcripts/:uniqueid", GetTranscriptionByUniqueID)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/transcripts/1234567890.99", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 ok, got %d: %s", w.Code, w.Body.String())
	}

	var response struct {
		Data struct {
			UniqueID      string `json:"uniqueid"`
			Transcription string `json:"transcription"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if response.Data.Transcription != "latest fragment transcript" {
		t.Fatalf("expected canonical (latest) transcript, got %q", response.Data.Transcription)
	}
}
