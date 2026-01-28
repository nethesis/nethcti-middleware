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

	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"

	"github.com/nethesis/nethcti-middleware/configuration"
	"github.com/nethesis/nethcti-middleware/models"
	"github.com/nethesis/nethcti-middleware/store"
)

func TestGetTranscription_UnauthorizedWhenNotParticipant(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store.UserSessionInit()
	store.UserSessions["alice"] = &models.UserSession{Username: "alice", NethCTIToken: "token"}

	configuration.Config.SatellitePgSQLHost = "test"
	configuration.Config.SatellitePgSQLPort = "5432"
	configuration.Config.SatellitePgSQLDB = "test"
	configuration.Config.SatellitePgSQLUser = "test"

	originalGetUserInfo := getUserInfoFunc
	originalCheck := checkUserParticipationFunc
	defer func() {
		getUserInfoFunc = originalGetUserInfo
		checkUserParticipationFunc = originalCheck
	}()

	getUserInfoFunc = func(string) (*UserInfo, error) {
		return &UserInfo{PhoneNumbers: []string{"100"}}, nil
	}
	checkUserParticipationFunc = func(string, []string) (bool, error) {
		return false, nil
	}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("JWT_PAYLOAD", jwt.MapClaims{"id": "alice"})
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

	var updatedSummary string
	updateSummaryFunc = func(uniqueID, summaryText string) (bool, error) {
		updatedSummary = summaryText
		return true, nil
	}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("JWT_PAYLOAD", jwt.MapClaims{"id": "alice"})
		c.Next()
	})
	router.PUT("/transcripts/summary/:uniqueid", UpdateSummaryByUniqueID)

	body, _ := json.Marshal(map[string]string{"summary": "test summary"})
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("PUT", "/transcripts/summary/abc123", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 ok, got %d: %s", w.Code, w.Body.String())
	}
	if updatedSummary != "test summary" {
		t.Fatalf("expected summary to be updated, got %q", updatedSummary)
	}
}
