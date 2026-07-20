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

func TestHistorySummaryLookupKey_PrefersUniqueID(t *testing.T) {
	cases := []struct {
		name     string
		linkedID string
		uniqueID string
		want     string
	}{
		{name: "both present prefers uniqueid (per-leg)", linkedID: "L-1", uniqueID: "U-2", want: "U-2"},
		{name: "uniqueid only", linkedID: "", uniqueID: "U-2", want: "U-2"},
		{name: "linkedid fallback when uniqueid missing", linkedID: "L-1", uniqueID: "", want: "L-1"},
		{name: "both empty", linkedID: "", uniqueID: "", want: ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := historySummaryLookupKey(tc.linkedID, tc.uniqueID); got != tc.want {
				t.Fatalf("historySummaryLookupKey(%q, %q) = %q, want %q", tc.linkedID, tc.uniqueID, got, tc.want)
			}
		})
	}
}

func TestGetFilteredHistory_ReturnsEmptyRowsWhenTranscriptsTableIsMissing(t *testing.T) {
	router, cleanup := setupHistoryArtifactTest(t, func([]string) ([]SummaryListItem, error) {
		return nil, &pgconn.PgError{Code: "42P01", Message: `relation "transcripts" does not exist`}
	})
	defer cleanup()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/history/calls?callType=user&username=alice&from=20260430&to=20260507&artifact=summary", nil)
	router.ServeHTTP(w, req)

	// A missing schema means no row has a summary yet, which is the same
	// outcome as a normal empty filter result, not an outage.
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 ok, got %d: %s", w.Code, w.Body.String())
	}

	var response struct {
		Count int                      `json:"count"`
		Rows  []map[string]interface{} `json:"rows"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if response.Count != 0 || len(response.Rows) != 0 {
		t.Fatalf("expected no rows, got %+v", response)
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
	originalResolveLinkedID := resolveLinkedIDToUniqueIDFunc
	originalFindSatelliteUIDs := findSatelliteUniqueIDsByLinkedIDFunc

	getUserInfoFunc = func(string) (*UserInfo, error) {
		return &UserInfo{PhoneNumbers: []string{"100"}}, nil
	}
	checkUserParticipationFunc = func(string, []string) (bool, error) {
		return true, nil
	}
	// Resolve the requested leg to a known uniqueid without touching the DB so
	// the artifact lookup reaches fetchSummaryListFunc (the seam under test).
	resolveLinkedIDToUniqueIDFunc = func(string, []string) (string, error) {
		return "uid-1", nil
	}
	findSatelliteUniqueIDsByLinkedIDFunc = func(string) ([]string, error) {
		return nil, nil
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
		resolveLinkedIDToUniqueIDFunc = originalResolveLinkedID
		findSatelliteUniqueIDsByLinkedIDFunc = originalFindSatelliteUIDs
	}

	return router, cleanup
}

func TestHistoryArtifactRowMatches(t *testing.T) {
	cases := []struct {
		name     string
		artifact string
		item     SummaryListItem
		want     bool
	}{
		{
			name:     "transcription filter keeps transcription-only call",
			artifact: historyArtifactTranscription,
			item:     SummaryListItem{State: "done", HasTranscription: true},
			want:     true,
		},
		{
			name:     "transcription filter keeps call that also has a summary",
			artifact: historyArtifactTranscription,
			item:     SummaryListItem{State: "done", HasTranscription: true, HasSummary: true},
			want:     true,
		},
		{
			name:     "transcription filter drops call without transcription",
			artifact: historyArtifactTranscription,
			item:     SummaryListItem{State: "done", HasSummary: true},
			want:     false,
		},
		{
			name:     "summary filter keeps call with summary and transcription",
			artifact: historyArtifactSummary,
			item:     SummaryListItem{State: "done", HasTranscription: true, HasSummary: true},
			want:     true,
		},
		{
			name:     "summary filter drops transcription-only call",
			artifact: historyArtifactSummary,
			item:     SummaryListItem{State: "done", HasTranscription: true},
			want:     false,
		},
		{
			name:     "non-done state is never matched",
			artifact: historyArtifactTranscription,
			item:     SummaryListItem{State: "processing", HasTranscription: true},
			want:     false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := historyArtifactRowMatches(tc.artifact, tc.item); got != tc.want {
				t.Fatalf("historyArtifactRowMatches(%q, %+v) = %v, want %v", tc.artifact, tc.item, got, tc.want)
			}
		})
	}
}

func TestCollapseHistoryRowsByLinkedid(t *testing.T) {
	rows := []map[string]interface{}{
		{"linkedid": "L1", "uniqueid": "u1a", "time": float64(300), "disposition": "NO ANSWER", "dst": "121"},
		{"linkedid": "L1", "uniqueid": "u1b", "time": float64(310), "disposition": "ANSWERED", "dst": "120"},
		{"linkedid": "L1", "uniqueid": "u1c", "time": float64(305), "disposition": "NO ANSWER", "dst": "122"},
		{"linkedid": "", "uniqueid": "u2", "time": float64(200), "disposition": "ANSWERED", "dst": "450"},
		{"linkedid": "L3", "uniqueid": "u3", "time": float64(100), "disposition": "NO ANSWER", "dst": "453"},
	}

	got := collapseHistoryRowsByLinkedid(rows)

	if len(got) != 3 {
		t.Fatalf("expected 3 parent rows, got %d", len(got))
	}
	// Order preserved: L1 group first (first-occurrence index 0), then standalone, then L3.
	if got[0]["linkedid"] != "L1" || got[1]["uniqueid"] != "u2" || got[2]["linkedid"] != "L3" {
		t.Fatalf("order not preserved: %+v", got)
	}
	// Parent of L1 is the ANSWERED leg.
	if got[0]["uniqueid"] != "u1b" {
		t.Fatalf("expected ANSWERED leg u1b as parent, got %v", got[0]["uniqueid"])
	}
	if got[0]["interactionsCount"] != 3 {
		t.Fatalf("expected interactionsCount 3, got %v", got[0]["interactionsCount"])
	}
	children, ok := got[0]["interactions"].([]map[string]interface{})
	if !ok || len(children) != 2 {
		t.Fatalf("expected 2 interaction children, got %v", got[0]["interactions"])
	}
	// Children exclude the parent and are ordered by ascending time (u1a@300, u1c@305).
	if children[0]["uniqueid"] != "u1a" || children[1]["uniqueid"] != "u1c" {
		t.Fatalf("children wrong/unsorted: %+v", children)
	}
	// Standalone (empty linkedid) and single-leg group have count 1 and no interactions.
	if got[1]["interactionsCount"] != 1 {
		t.Fatalf("standalone count should be 1, got %v", got[1]["interactionsCount"])
	}
	if _, has := got[2]["interactions"]; has {
		t.Fatalf("single-leg group must not have interactions")
	}
	if got[2]["interactionsCount"] != 1 {
		t.Fatalf("single-leg count should be 1, got %v", got[2]["interactionsCount"])
	}
}

// TestCollapseHistoryRowsByLinkedid_NoAnsweredLeg proves that when a linkedid
// group has no ANSWERED leg, selectParentLegIndex falls back to 0 (the first
// leg) and the parent's interactions are the remaining legs ordered by
// ascending time.
func TestCollapseHistoryRowsByLinkedid_NoAnsweredLeg(t *testing.T) {
	rows := []map[string]interface{}{
		{"linkedid": "L1", "uniqueid": "u1a", "time": float64(300), "disposition": "NO ANSWER", "dst": "121"},
		{"linkedid": "L1", "uniqueid": "u1b", "time": float64(100), "disposition": "BUSY", "dst": "120"},
		{"linkedid": "L1", "uniqueid": "u1c", "time": float64(200), "disposition": "NO ANSWER", "dst": "122"},
	}

	got := collapseHistoryRowsByLinkedid(rows)

	if len(got) != 1 {
		t.Fatalf("expected 1 parent row, got %d", len(got))
	}
	// No ANSWERED leg in the group: parent falls back to the EARLIEST leg
	// deterministically (u1b@100), independent of input order.
	if got[0]["uniqueid"] != "u1b" {
		t.Fatalf("expected earliest leg u1b as fallback parent, got %v", got[0]["uniqueid"])
	}
	if got[0]["interactionsCount"] != 3 {
		t.Fatalf("expected interactionsCount 3, got %v", got[0]["interactionsCount"])
	}
	children, ok := got[0]["interactions"].([]map[string]interface{})
	if !ok || len(children) != 2 {
		t.Fatalf("expected 2 interaction children, got %v", got[0]["interactions"])
	}
	// Children exclude the parent and are ordered by ascending time (u1c@200, u1a@300).
	if children[0]["uniqueid"] != "u1c" || children[1]["uniqueid"] != "u1a" {
		t.Fatalf("children wrong/unsorted: %+v", children)
	}
}

func TestCollapseHistoryRowsByLinkedid_ParentIsAgentNotQueue(t *testing.T) {
	// A queue call: caller 202 → queue 401, answered by agent 203. Both the
	// queue-entry leg (lastapp=Queue, dst=401) and the agent Dial leg
	// (dst=203) are ANSWERED. The parent must be the agent leg so the row's
	// destination is WHO answered, not the queue number.
	rows := []map[string]interface{}{
		{"linkedid": "L1", "uniqueid": "uQueue", "time": float64(100), "disposition": "ANSWERED", "lastapp": "Queue", "src": "202", "dst": "401"},
		{"linkedid": "L1", "uniqueid": "uRing201", "time": float64(101), "disposition": "ANSWERED_ELSEWHERE", "lastapp": "Dial", "src": "202", "dst": "201"},
		{"linkedid": "L1", "uniqueid": "uAgent203", "time": float64(102), "disposition": "ANSWERED", "lastapp": "Dial", "src": "202", "dst": "203"},
	}

	got := collapseHistoryRowsByLinkedid(rows)

	if len(got) != 1 {
		t.Fatalf("expected 1 parent row, got %d", len(got))
	}
	if got[0]["uniqueid"] != "uAgent203" {
		t.Fatalf("expected agent Dial leg uAgent203 as parent, got %v", got[0]["uniqueid"])
	}
	if got[0]["dst"] != "203" {
		t.Fatalf("expected parent dst 203 (who answered), got %v", got[0]["dst"])
	}
	if got[0]["interactionsCount"] != 3 {
		t.Fatalf("expected interactionsCount 3, got %v", got[0]["interactionsCount"])
	}
}

func TestCollapseHistoryRowsByLinkedid_StableParentAcrossSortOrder(t *testing.T) {
	// A transferred call has multiple ANSWERED legs. The parent must be the
	// earliest ANSWERED leg regardless of the order rows arrive in (which varies
	// with the request sort), so the same call always exposes the same parent.
	asc := []map[string]interface{}{
		{"linkedid": "L1", "uniqueid": "uEarly", "time": float64(100), "disposition": "ANSWERED", "dst": "120"},
		{"linkedid": "L1", "uniqueid": "uLate", "time": float64(200), "disposition": "ANSWERED", "dst": "121"},
	}
	desc := []map[string]interface{}{
		{"linkedid": "L1", "uniqueid": "uLate", "time": float64(200), "disposition": "ANSWERED", "dst": "121"},
		{"linkedid": "L1", "uniqueid": "uEarly", "time": float64(100), "disposition": "ANSWERED", "dst": "120"},
	}

	gotAsc := collapseHistoryRowsByLinkedid(asc)
	gotDesc := collapseHistoryRowsByLinkedid(desc)

	if gotAsc[0]["uniqueid"] != "uEarly" || gotDesc[0]["uniqueid"] != "uEarly" {
		t.Fatalf("parent not stable/earliest across order: asc=%v desc=%v",
			gotAsc[0]["uniqueid"], gotDesc[0]["uniqueid"])
	}
}
