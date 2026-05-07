/*
 * Copyright (C) 2026 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package methods

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/nethesis/nethcti-middleware/configuration"
	"github.com/nethesis/nethcti-middleware/logs"
	"github.com/nethesis/nethcti-middleware/store"
	"github.com/nethesis/nethcti-middleware/summary"
)

const (
	historyArtifactAll           = "all"
	historyArtifactSummary       = "summary"
	historyArtifactTranscription = "transcription"
	historyArtifactVoicemail     = "voicemail"
	defaultHistoryPageSize       = 10
)

type historyFilterResponse struct {
	Count int                      `json:"count"`
	Rows  []map[string]interface{} `json:"rows"`
}

type historyFilterRequest struct {
	CallType    string
	Username    string
	From        string
	To          string
	TextSearch  string
	Sort        string
	Direction   string
	PageNum     int
	PageSize    int
	Artifact    string
	LegacyToken string
}

// GetFilteredHistory returns history rows filtered server-side by voicemail,
// summary or transcription and keeps count/pagination consistent.
func GetFilteredHistory(c *gin.Context) {
	req, err := parseHistoryFilterRequest(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    http.StatusBadRequest,
			"message": err.Error(),
		})
		return
	}

	baseResponse, err := fetchLegacyHistoryFromV1(req)
	if err != nil {
		logs.Log("[ERROR][HISTORY] Failed to fetch legacy history: " + err.Error())
		c.JSON(http.StatusBadGateway, gin.H{
			"code":    http.StatusBadGateway,
			"message": err.Error(),
		})
		return
	}

	filteredRows, err := filterHistoryRowsByArtifact(c, req.Artifact, baseResponse.Rows)
	if err != nil {
		if isSatelliteSchemaMissingError(err) {
			logs.Log("[WARNING][HISTORY] Satellite schema is not initialized while filtering history rows: " + err.Error())
			writeSatelliteSchemaMissingResponse(c)
			return
		}
		if isSatelliteDBUnavailableError(err) {
			logs.Log("[WARNING][HISTORY] Satellite database is unavailable while filtering history rows: " + err.Error())
			writeSatelliteDBUnavailableResponse(c)
			return
		}

		statusCode := http.StatusInternalServerError
		if strings.Contains(err.Error(), "satellite database not configured") {
			statusCode = http.StatusServiceUnavailable
		}

		logs.Log("[ERROR][HISTORY] Failed to filter history rows: " + err.Error())
		c.JSON(statusCode, gin.H{
			"code":    statusCode,
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, paginateHistoryRows(filteredRows, req.PageNum, req.PageSize))
}

func parseHistoryFilterRequest(c *gin.Context) (*historyFilterRequest, error) {
	callType := strings.TrimSpace(c.Query("callType"))
	username := strings.TrimSpace(c.Query("username"))
	from := strings.TrimSpace(c.Query("from"))
	to := strings.TrimSpace(c.Query("to"))
	artifact := strings.TrimSpace(c.DefaultQuery("artifact", historyArtifactAll))
	textSearch := strings.TrimSpace(c.Query("textSearch"))
	sortBy := strings.TrimSpace(c.DefaultQuery("sort", "time%20desc"))
	direction := strings.TrimSpace(c.DefaultQuery("direction", "all"))

	if callType == "" || username == "" || from == "" || to == "" {
		return nil, fmt.Errorf("callType, username, from and to are required")
	}

	if artifact != historyArtifactSummary &&
		artifact != historyArtifactTranscription &&
		artifact != historyArtifactVoicemail &&
		artifact != historyArtifactAll {
		return nil, fmt.Errorf("invalid artifact filter")
	}

	usernameFromClaims, err := getUsernameFromContext(c)
	if err != nil {
		return nil, fmt.Errorf("unauthorized")
	}

	userSession := store.UserSessions[usernameFromClaims]
	if userSession == nil || strings.TrimSpace(userSession.NethCTIToken) == "" {
		return nil, fmt.Errorf("user session not found")
	}

	pageNum, err := parsePositiveInt(c.DefaultQuery("pageNum", "1"), 1)
	if err != nil {
		return nil, fmt.Errorf("invalid pageNum")
	}

	pageSize, err := parsePositiveInt(c.DefaultQuery("pageSize", strconv.Itoa(defaultHistoryPageSize)), defaultHistoryPageSize)
	if err != nil {
		return nil, fmt.Errorf("invalid pageSize")
	}

	return &historyFilterRequest{
		CallType:    callType,
		Username:    username,
		From:        from,
		To:          to,
		TextSearch:  textSearch,
		Sort:        sortBy,
		Direction:   direction,
		PageNum:     pageNum,
		PageSize:    pageSize,
		Artifact:    artifact,
		LegacyToken: userSession.NethCTIToken,
	}, nil
}

func parsePositiveInt(raw string, fallback int) (int, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return fallback, nil
	}

	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("invalid positive integer")
	}

	return parsed, nil
}

func fetchLegacyHistoryFromV1(req *historyFilterRequest) (*historyFilterResponse, error) {
	if configuration.Config.V1ApiEndpoint == "" {
		return nil, fmt.Errorf("V1 API endpoint not configured")
	}

	path, queryValues, err := buildLegacyHistoryPath(req)
	if err != nil {
		return nil, err
	}

	requestURL := configuration.Config.V1Protocol + "://" + configuration.Config.V1ApiEndpoint + configuration.Config.V1ApiPath + path
	if encoded := queryValues.Encode(); encoded != "" {
		requestURL += "?" + encoded
	}

	httpReq, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Authorization", req.LegacyToken)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		bodyText := strings.TrimSpace(string(bodyBytes))
		if bodyText == "" {
			return nil, fmt.Errorf("legacy history upstream returned status %d", resp.StatusCode)
		}
		return nil, fmt.Errorf("legacy history upstream returned status %d: %s", resp.StatusCode, bodyText)
	}

	var payload historyFilterResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}

	if payload.Rows == nil {
		payload.Rows = []map[string]interface{}{}
	}

	return &payload, nil
}

func buildLegacyHistoryPath(req *historyFilterRequest) (string, url.Values, error) {
	queryValues := url.Values{}
	sortValue := req.Sort
	if decodedSort, err := url.QueryUnescape(req.Sort); err == nil && strings.TrimSpace(decodedSort) != "" {
		sortValue = decodedSort
	}
	queryValues.Set("sort", sortValue)

	removeLostCalls := "false"
	if req.Direction == "in" {
		removeLostCalls = "true"
	}
	queryValues.Set("removeLostCalls", removeLostCalls)

	var path string
	switch req.CallType {
	case "switchboard":
		path = "/histcallswitch/interval/" + req.From + "/" + req.To
		if req.TextSearch != "" {
			path += "/" + url.PathEscape(req.TextSearch)
		}
		if req.Direction != "" && req.Direction != "all" {
			queryValues.Set("type", req.Direction)
		}
	case "group", "groups":
		path = "/histcallsgroups/interval/" + req.From + "/" + req.To
		if req.TextSearch != "" {
			path += "/" + url.PathEscape(req.TextSearch)
		}
		if req.Direction != "" && req.Direction != "all" {
			queryValues.Set("type", req.Direction)
		}
	default:
		path = "/historycall/interval/" + req.CallType + "/" + url.PathEscape(req.Username) + "/" + req.From + "/" + req.To
		if req.TextSearch != "" {
			path += "/" + url.PathEscape(req.TextSearch)
		}
		if req.Direction != "" && req.Direction != "all" {
			queryValues.Set("direction", req.Direction)
		}
	}

	return path, queryValues, nil
}

func filterHistoryRowsByArtifact(c *gin.Context, artifact string, rows []map[string]interface{}) ([]map[string]interface{}, error) {
	switch artifact {
	case historyArtifactAll:
		return rows, nil
	case historyArtifactVoicemail:
		filtered := make([]map[string]interface{}, 0, len(rows))
		for _, row := range rows {
			if hasHistoryVoicemail(row) {
				filtered = append(filtered, row)
			}
		}
		return filtered, nil
	case historyArtifactSummary, historyArtifactTranscription:
		if !summary.IsSatelliteDBConfigured() {
			return nil, fmt.Errorf("satellite database not configured")
		}

		linkedIDs := collectHistoryLinkedIDs(rows)
		if len(linkedIDs) == 0 {
			return []map[string]interface{}{}, nil
		}

		authorizedIDs, err := filterSummaryStatusUniqueIDsByParticipation(c, linkedIDs)
		if err != nil {
			return nil, err
		}

		statusItems, err := fetchSummaryListFunc(authorizedIDs)
		if err != nil {
			return nil, err
		}

		statusMap := make(map[string]SummaryListItem, len(statusItems))
		for _, item := range statusItems {
			statusMap[item.UniqueID] = item
		}

		filtered := make([]map[string]interface{}, 0, len(rows))
		for _, row := range rows {
			linkedID := strings.TrimSpace(getHistoryRowString(row, "linkedid"))
			if linkedID == "" {
				continue
			}

			item, ok := statusMap[linkedID]
			if !ok || strings.TrimSpace(item.State) != "done" {
				continue
			}

			if artifact == historyArtifactSummary && item.HasSummary {
				filtered = append(filtered, row)
				continue
			}

			if artifact == historyArtifactTranscription && item.HasTranscription && !item.HasSummary {
				filtered = append(filtered, row)
			}
		}

		return filtered, nil
	default:
		return rows, nil
	}
}

func collectHistoryLinkedIDs(rows []map[string]interface{}) []string {
	collected := make([]string, 0, len(rows))
	seen := make(map[string]struct{})

	for _, row := range rows {
		linkedID := strings.TrimSpace(getHistoryRowString(row, "linkedid"))
		if linkedID == "" {
			continue
		}
		if _, ok := seen[linkedID]; ok {
			continue
		}
		seen[linkedID] = struct{}{}
		collected = append(collected, linkedID)
	}

	return collected
}

func hasHistoryVoicemail(row map[string]interface{}) bool {
	if value, ok := row["has_voicemail_message"].(bool); ok && value {
		return true
	}

	return strings.TrimSpace(getHistoryRowString(row, "voicemail_message_id")) != ""
}

func getHistoryRowString(row map[string]interface{}, key string) string {
	value, ok := row[key]
	if !ok || value == nil {
		return ""
	}

	switch typed := value.(type) {
	case string:
		return typed
	case fmt.Stringer:
		return typed.String()
	default:
		return fmt.Sprintf("%v", typed)
	}
}

func paginateHistoryRows(rows []map[string]interface{}, pageNum int, pageSize int) gin.H {
	count := len(rows)
	start := (pageNum - 1) * pageSize
	if start > count {
		start = count
	}

	end := start + pageSize
	if end > count {
		end = count
	}

	return gin.H{
		"count": count,
		"rows":  rows[start:end],
	}
}
