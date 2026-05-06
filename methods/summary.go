/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package methods

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/fatih/structs"
	"github.com/gin-gonic/gin"
	"github.com/nethesis/nethcti-middleware/db"
	"github.com/nethesis/nethcti-middleware/logs"
	"github.com/nethesis/nethcti-middleware/models"
	"github.com/nethesis/nethcti-middleware/summary"
)

type SummaryWatchRequest struct {
	UniqueID string `json:"uniqueid"`
	LinkedID string `json:"linkedid,omitempty"`
}

type SummaryUpdateRequest struct {
	Summary string `json:"summary"`
}

type SummaryDrawer struct {
	UniqueID      string     `json:"uniqueid"`
	Summary       string     `json:"summary"`
	Sentiment     *int       `json:"sentiment,omitempty"`
	State         string     `json:"state"`
	Src           string     `json:"src,omitempty"`
	Dst           string     `json:"dst,omitempty"`
	CNam          string     `json:"cnam,omitempty"`
	Company       string     `json:"company,omitempty"`
	DstCompany    string     `json:"dst_company,omitempty"`
	DstCNam       string     `json:"dst_cnam,omitempty"`
	CallTimestamp *time.Time `json:"call_timestamp,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	DeletedAt     *time.Time `json:"deleted_at,omitempty"`
}

type CallMetadata struct {
	Src           string
	Dst           string
	CNam          string
	Company       string
	DstCompany    string
	DstCNam       string
	CallTimestamp *time.Time
}

type SummaryListItem struct {
	LinkedID         string     `json:"linkedid,omitempty"`
	UniqueID         string     `json:"uniqueid"`
	State            string     `json:"state"`
	HasTranscription bool       `json:"has_transcription"`
	HasSummary       bool       `json:"has_summary"`
	UpdatedAt        *time.Time `json:"updated_at"`
}

var (
	fetchSummaryDrawerFunc                     = fetchSummaryDrawerFromDB
	fetchSummaryListFunc                       = fetchSummaryListFromDB
	fetchSummaryStateFunc                      = fetchSummaryStateFromDB
	fetchSummaryFunc                           = fetchSummaryFromDB
	updateSummaryFunc                          = updateSummaryInDB
	deleteSummaryFunc                          = deleteSummaryInDB
	startSummaryWatchFunc = summary.StartSummaryWatchWithLinkedID
)

func getUniqueIDFromPath(c *gin.Context) string {
	return strings.TrimSpace(c.Param("uniqueid"))
}

type SummaryStatusLookup struct {
	UniqueID string `json:"uniqueid,omitempty"`
	LinkedID string `json:"linkedid,omitempty"`
}

type resolvedSummaryStatusLookup struct {
	UniqueID         string
	LinkedID         string
	ResolvedUniqueID string
}

// WatchCallSummary starts watching for a summary in the satellite transcripts table.
func WatchCallSummary(c *gin.Context) {
	var req SummaryWatchRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, structs.Map(models.StatusBadRequest{
			Code:    http.StatusBadRequest,
			Message: "invalid request payload",
			Data:    err.Error(),
		}))
		return
	}

	uniqueIDHint := strings.TrimSpace(req.UniqueID)
	linkedID := strings.TrimSpace(req.LinkedID)
	if uniqueIDHint == "" {
		c.JSON(http.StatusBadRequest, structs.Map(models.StatusBadRequest{
			Code:    http.StatusBadRequest,
			Message: "uniqueid is required",
			Data:    nil,
		}))
		return
	}

	if !summary.IsSatelliteDBConfigured() {
		c.JSON(http.StatusServiceUnavailable, structs.Map(models.StatusServiceUnavailable{
			Code:    http.StatusServiceUnavailable,
			Message: "satellite database not configured",
			Data:    nil,
		}))
		return
	}

	username, err := getUsernameFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, structs.Map(models.StatusUnauthorized{
			Code:    http.StatusUnauthorized,
			Message: "unauthorized",
			Data:    nil,
		}))
		return
	}

	uniqueID, _, _, ok, err := ensureUserParticipatedInCall(c, uniqueIDHint, linkedID)
	if err != nil {
		if errors.Is(err, errUnauthorized) {
			c.JSON(http.StatusUnauthorized, structs.Map(models.StatusUnauthorized{
				Code:    http.StatusUnauthorized,
				Message: "unauthorized",
				Data:    nil,
			}))
			return
		}
		logs.Log("[ERROR][SUMMARY] Failed to validate CDR participation for watch uniqueid " + uniqueIDHint + ": " + err.Error())
		c.JSON(http.StatusServiceUnavailable, structs.Map(models.StatusServiceUnavailable{
			Code:    http.StatusServiceUnavailable,
			Message: "cdr database unavailable",
			Data:    nil,
		}))
		return
	}
	if !ok {
		logForbiddenParticipation(c, uniqueIDHint)
		c.JSON(http.StatusForbidden, structs.Map(models.StatusForbidden{
			Code:    http.StatusForbidden,
			Message: "forbidden: user not part of call",
			Data:    nil,
		}))
		return
	}

	startResult := startSummaryWatchFunc(uniqueID, linkedID, username)
	if startResult != summary.WatchStarted {
		message := "watch unavailable"
		switch startResult {
		case summary.WatchAlreadyActive:
			logs.Log("[INFO][SUMMARY] Watch already active for user " + username + " uniqueid: " + uniqueID)
			message = "watch already active"
		case summary.WatchMisconfigured:
			logs.Log("[WARNING][SUMMARY] Watch unavailable due to missing configuration for user " + username + " uniqueid: " + uniqueID)
			message = "watch unavailable: missing configuration"
		default:
			logs.Log("[WARNING][SUMMARY] Watch unavailable due to invalid input for user " + username + " uniqueid: " + uniqueID)
			message = "watch unavailable"
		}
		c.JSON(http.StatusOK, structs.Map(models.StatusOK{
			Code:    http.StatusOK,
			Message: message,
			Data:    nil,
		}))
		return
	}

	logs.Log("[INFO][SUMMARY] Watch started for user " + username + " uniqueid: " + uniqueID)
	c.JSON(http.StatusAccepted, structs.Map(models.StatusOK{
		Code:    http.StatusAccepted,
		Message: "watch started",
		Data:    nil,
	}))
}

// CheckSummaryByUniqueID verifies whether a non-deleted summary exists for the given uniqueid.
// It is intended for HEAD endpoints and returns status only (no response body).
func CheckSummaryByUniqueID(c *gin.Context) {
	uniqueIDHint := getUniqueIDFromPath(c)
	linkedID := getLinkedIDFromQuery(c)
	if uniqueIDHint == "" {
		c.Status(http.StatusBadRequest)
		return
	}

	if !summary.IsSatelliteDBConfigured() {
		c.Status(http.StatusServiceUnavailable)
		return
	}

	uniqueID, _, _, ok, err := ensureUserParticipatedInCall(c, uniqueIDHint, linkedID)
	if err != nil {
		if errors.Is(err, errUnauthorized) {
			c.Status(http.StatusUnauthorized)
			return
		}
		logs.Log("[ERROR][SUMMARY] Failed to validate CDR participation for uniqueid " + uniqueIDHint + ": " + err.Error())
		c.Status(http.StatusServiceUnavailable)
		return
	}
	if !ok {
		logForbiddenParticipation(c, uniqueIDHint)
		c.Status(http.StatusForbidden)
		return
	}

	state, hasSummary, _, exists, err := fetchSummaryStateFunc(uniqueID)
	if err != nil {
		logs.Log("[ERROR][SUMMARY] Failed to fetch summary for uniqueid " + uniqueID + ": " + err.Error())
		c.Status(http.StatusInternalServerError)
		return
	}

	foundRecord := exists
	keepWaiting := shouldKeepWaitingForSummary(state)

	if hasSummary {
		c.Status(http.StatusOK)
		return
	}

	if keepWaiting {
		c.Status(http.StatusNoContent)
		return
	}

	if !foundRecord {
		if linkedID != "" {
			c.Status(http.StatusNoContent)
			return
		}
		c.Status(http.StatusNotFound)
		return
	}

	c.Status(http.StatusNotFound)
}

func shouldKeepWaitingForSummary(state string) bool {
	switch strings.TrimSpace(state) {
	case "progress", "summarizing":
		return true
	default:
		return false
	}
}

// GetSummaryByUniqueID returns the summary for the given uniqueid.
func GetSummaryByUniqueID(c *gin.Context) {
	uniqueIDHint := getUniqueIDFromPath(c)
	linkedID := getLinkedIDFromQuery(c)
	if uniqueIDHint == "" {
		c.JSON(http.StatusBadRequest, structs.Map(models.StatusBadRequest{
			Code:    http.StatusBadRequest,
			Message: "uniqueid is required",
			Data:    nil,
		}))
		return
	}

	if !summary.IsSatelliteDBConfigured() {
		c.JSON(http.StatusServiceUnavailable, structs.Map(models.StatusServiceUnavailable{
			Code:    http.StatusServiceUnavailable,
			Message: "satellite database not configured",
			Data:    nil,
		}))
		return
	}

	uniqueID, phoneNumbers, excludedSrcNums, ok, err := ensureUserParticipatedInCall(c, uniqueIDHint, linkedID)
	if err != nil {
		if errors.Is(err, errUnauthorized) {
			c.JSON(http.StatusUnauthorized, structs.Map(models.StatusUnauthorized{
				Code:    http.StatusUnauthorized,
				Message: "unauthorized",
				Data:    nil,
			}))
			return
		}
		logs.Log("[ERROR][SUMMARY] Failed to validate CDR participation for uniqueid " + uniqueIDHint + ": " + err.Error())
		c.JSON(http.StatusServiceUnavailable, structs.Map(models.StatusServiceUnavailable{
			Code:    http.StatusServiceUnavailable,
			Message: "cdr database unavailable",
			Data:    nil,
		}))
		return
	}
	if !ok {
		logForbiddenParticipation(c, uniqueIDHint)
		c.JSON(http.StatusForbidden, structs.Map(models.StatusForbidden{
			Code:    http.StatusForbidden,
			Message: "forbidden: user not part of call",
			Data:    nil,
		}))
		return
	}

	details, found, err := fetchSummaryDrawerFunc(uniqueID, phoneNumbers, excludedSrcNums)
	if err != nil {
		logs.Log("[ERROR][SUMMARY] Failed to fetch summary for uniqueid " + uniqueID + ": " + err.Error())
		c.JSON(http.StatusInternalServerError, structs.Map(models.StatusInternalServerError{
			Code:    http.StatusInternalServerError,
			Message: "failed to fetch summary",
			Data:    nil,
		}))
		return
	}

	if !found {
		c.JSON(http.StatusNotFound, structs.Map(models.StatusNotFound{
			Code:    http.StatusNotFound,
			Message: "summary not found",
			Data:    nil,
		}))
		return
	}

	c.JSON(http.StatusOK, models.StatusOK{
		Code:    http.StatusOK,
		Message: "success",
		Data:    details,
	})
}

// DeleteSummaryByUniqueID removes the summary for the given uniqueid.
func DeleteSummaryByUniqueID(c *gin.Context) {
	uniqueIDHint := getUniqueIDFromPath(c)
	linkedID := getLinkedIDFromQuery(c)
	if uniqueIDHint == "" {
		c.JSON(http.StatusBadRequest, structs.Map(models.StatusBadRequest{
			Code:    http.StatusBadRequest,
			Message: "uniqueid is required",
			Data:    nil,
		}))
		return
	}

	if !summary.IsSatelliteDBConfigured() {
		c.JSON(http.StatusServiceUnavailable, structs.Map(models.StatusServiceUnavailable{
			Code:    http.StatusServiceUnavailable,
			Message: "satellite database not configured",
			Data:    nil,
		}))
		return
	}

	uniqueID, _, _, ok, err := ensureUserParticipatedInCall(c, uniqueIDHint, linkedID)
	if err != nil {
		if errors.Is(err, errUnauthorized) {
			c.JSON(http.StatusUnauthorized, structs.Map(models.StatusUnauthorized{
				Code:    http.StatusUnauthorized,
				Message: "unauthorized",
				Data:    nil,
			}))
			return
		}
		logs.Log("[ERROR][SUMMARY] Failed to validate CDR participation for uniqueid " + uniqueIDHint + ": " + err.Error())
		c.JSON(http.StatusServiceUnavailable, structs.Map(models.StatusServiceUnavailable{
			Code:    http.StatusServiceUnavailable,
			Message: "cdr database unavailable",
			Data:    nil,
		}))
		return
	}
	if !ok {
		logForbiddenParticipation(c, uniqueIDHint)
		c.JSON(http.StatusForbidden, structs.Map(models.StatusForbidden{
			Code:    http.StatusForbidden,
			Message: "forbidden: user not part of call",
			Data:    nil,
		}))
		return
	}

	deleted, err := deleteSummaryFunc(uniqueID)
	if err != nil {
		logs.Log("[ERROR][SUMMARY] Failed to delete summary for uniqueid " + uniqueID + ": " + err.Error())
		c.JSON(http.StatusInternalServerError, structs.Map(models.StatusInternalServerError{
			Code:    http.StatusInternalServerError,
			Message: "failed to delete summary",
			Data:    nil,
		}))
		return
	}

	if !deleted {
		c.JSON(http.StatusNotFound, structs.Map(models.StatusNotFound{
			Code:    http.StatusNotFound,
			Message: "summary not found",
			Data:    nil,
		}))
		return
	}

	c.JSON(http.StatusOK, structs.Map(models.StatusOK{
		Code:    http.StatusOK,
		Message: "summary deleted",
		Data: gin.H{
			"uniqueid": uniqueID,
		},
	}))
}

// UpdateSummaryByUniqueID updates the summary for the given uniqueid.
func UpdateSummaryByUniqueID(c *gin.Context) {
	uniqueIDHint := getUniqueIDFromPath(c)
	linkedID := getLinkedIDFromQuery(c)
	if uniqueIDHint == "" {
		c.JSON(http.StatusBadRequest, structs.Map(models.StatusBadRequest{
			Code:    http.StatusBadRequest,
			Message: "uniqueid is required",
			Data:    nil,
		}))
		return
	}

	var req SummaryUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, structs.Map(models.StatusBadRequest{
			Code:    http.StatusBadRequest,
			Message: "invalid request payload",
			Data:    err.Error(),
		}))
		return
	}

	summaryText := strings.TrimSpace(req.Summary)
	if summaryText == "" {
		c.JSON(http.StatusBadRequest, structs.Map(models.StatusBadRequest{
			Code:    http.StatusBadRequest,
			Message: "summary is required",
			Data:    nil,
		}))
		return
	}

	if !summary.IsSatelliteDBConfigured() {
		c.JSON(http.StatusServiceUnavailable, structs.Map(models.StatusServiceUnavailable{
			Code:    http.StatusServiceUnavailable,
			Message: "satellite database not configured",
			Data:    nil,
		}))
		return
	}

	uniqueID, _, _, ok, err := ensureUserParticipatedInCall(c, uniqueIDHint, linkedID)
	if err != nil {
		if errors.Is(err, errUnauthorized) {
			c.JSON(http.StatusUnauthorized, structs.Map(models.StatusUnauthorized{
				Code:    http.StatusUnauthorized,
				Message: "unauthorized",
				Data:    nil,
			}))
			return
		}
		logs.Log("[ERROR][SUMMARY] Failed to validate CDR participation for uniqueid " + uniqueIDHint + ": " + err.Error())
		c.JSON(http.StatusServiceUnavailable, structs.Map(models.StatusServiceUnavailable{
			Code:    http.StatusServiceUnavailable,
			Message: "cdr database unavailable",
			Data:    nil,
		}))
		return
	}
	if !ok {
		logForbiddenParticipation(c, uniqueIDHint)
		c.JSON(http.StatusForbidden, structs.Map(models.StatusForbidden{
			Code:    http.StatusForbidden,
			Message: "forbidden: user not part of call",
			Data:    nil,
		}))
		return
	}

	updated, err := updateSummaryFunc(uniqueID, summaryText)
	if err != nil {
		logs.Log("[ERROR][SUMMARY] Failed to update summary for uniqueid " + uniqueID + ": " + err.Error())
		c.JSON(http.StatusInternalServerError, structs.Map(models.StatusInternalServerError{
			Code:    http.StatusInternalServerError,
			Message: "failed to update summary",
			Data:    nil,
		}))
		return
	}

	if !updated {
		c.JSON(http.StatusNotFound, structs.Map(models.StatusNotFound{
			Code:    http.StatusNotFound,
			Message: "summary not found",
			Data:    nil,
		}))
		return
	}

	c.JSON(http.StatusOK, structs.Map(models.StatusOK{
		Code:    http.StatusOK,
		Message: "summary updated",
		Data: gin.H{
			"uniqueid": uniqueID,
			"summary":  summaryText,
		},
	}))
}

// ListSummaryStatus returns the list of summary/transcription status for user's calls.
func ListSummaryStatus(c *gin.Context) {
	if !summary.IsSatelliteDBConfigured() {
		c.JSON(http.StatusServiceUnavailable, structs.Map(models.StatusServiceUnavailable{
			Code:    http.StatusServiceUnavailable,
			Message: "satellite database not configured",
			Data:    nil,
		}))
		return
	}

	lookups, err := extractSummaryStatusLookups(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, structs.Map(models.StatusBadRequest{
			Code:    http.StatusBadRequest,
			Message: "invalid request payload",
			Data:    err.Error(),
		}))
		return
	}

	if len(lookups) == 0 {
		c.JSON(http.StatusBadRequest, structs.Map(models.StatusBadRequest{
			Code:    http.StatusBadRequest,
			Message: "uniqueids is required",
			Data:    nil,
		}))
		return
	}

	resolvedLookups, err := resolveSummaryStatusLookups(c, lookups)
	if err != nil {
		if errors.Is(err, errUnauthorized) {
			c.JSON(http.StatusUnauthorized, structs.Map(models.StatusUnauthorized{
				Code:    http.StatusUnauthorized,
				Message: "unauthorized",
				Data:    nil,
			}))
			return
		}

		logs.Log("[ERROR][SUMMARY] Failed to validate CDR participation for statuses: " + err.Error())
		c.JSON(http.StatusServiceUnavailable, structs.Map(models.StatusServiceUnavailable{
			Code:    http.StatusServiceUnavailable,
			Message: "cdr database unavailable",
			Data:    nil,
		}))
		return
	}

	resolvedUniqueIDs := collectResolvedUniqueIDs(resolvedLookups)
	items, err := fetchSummaryListFunc(resolvedUniqueIDs)
	if err != nil {
		logs.Log("[ERROR][SUMMARY] Failed to list summaries: " + err.Error())
		c.JSON(http.StatusInternalServerError, structs.Map(models.StatusInternalServerError{
			Code:    http.StatusInternalServerError,
			Message: "failed to list summaries",
			Data:    nil,
		}))
		return
	}

	itemByUniqueID := make(map[string]SummaryListItem, len(items))
	for _, item := range items {
		itemByUniqueID[item.UniqueID] = item
	}

	// Track which uniqueids are already included in the result
	includedUIDs := make(map[string]struct{})

	result := make([]interface{}, 0, len(resolvedLookups))
	for _, lookup := range resolvedLookups {
		if item, ok := itemByUniqueID[lookup.ResolvedUniqueID]; ok {
			item.LinkedID = lookup.LinkedID
			// Use the requested uniqueid so the frontend can match
			// the response entry to the correct history row.
			if lookup.UniqueID != "" {
				item.UniqueID = lookup.UniqueID
			}
			result = append(result, item)
			includedUIDs[lookup.ResolvedUniqueID] = struct{}{}
			continue
		}
		reportedUniqueID := lookup.UniqueID
		if reportedUniqueID == "" {
			reportedUniqueID = lookup.ResolvedUniqueID
		}
		result = append(result, gin.H{
			"uniqueid": reportedUniqueID,
			"linkedid": lookup.LinkedID,
			"error":    "not_found",
		})
	}

	// NOTE: Satellite extra discovery (consultation segments without CDR rows)
	// is intentionally disabled. The frontend currently cannot display items
	// that don't correspond to a history row. Consultation transcriptions
	// remain accessible via GET /summary/:uniqueid when explicitly requested.

	c.JSON(http.StatusOK, structs.Map(models.StatusOK{
		Code:    http.StatusOK,
		Message: "success",
		Data:    result,
	}))
}

func extractSummaryStatusLookups(c *gin.Context) ([]SummaryStatusLookup, error) {
	var req struct {
		UniqueIDs []string              `json:"uniqueids"`
		Lookups   []SummaryStatusLookup `json:"lookups"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		return nil, err
	}

	if len(req.Lookups) > 0 {
		return normalizeSummaryStatusLookups(req.Lookups), nil
	}

	if len(req.UniqueIDs) == 0 {
		return []SummaryStatusLookup{}, nil
	}

	normalizedUniqueIDs := normalizeLookupIDs(req.UniqueIDs)
	lookups := make([]SummaryStatusLookup, 0, len(normalizedUniqueIDs))
	for _, uniqueID := range normalizedUniqueIDs {
		lookups = append(lookups, SummaryStatusLookup{UniqueID: uniqueID})
	}
	return lookups, nil
}

func normalizeSummaryStatusLookups(lookups []SummaryStatusLookup) []SummaryStatusLookup {
	cleaned := make([]SummaryStatusLookup, 0, len(lookups))
	seen := make(map[string]struct{})

	for _, lookup := range lookups {
		normalized := SummaryStatusLookup{
			UniqueID: strings.TrimSpace(lookup.UniqueID),
			LinkedID: strings.TrimSpace(lookup.LinkedID),
		}
		if normalized.UniqueID == "" && normalized.LinkedID == "" {
			continue
		}

		key := normalized.UniqueID
		if key == "" {
			key = normalized.LinkedID
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		cleaned = append(cleaned, normalized)
	}

	return cleaned
}

func resolveSummaryStatusLookups(c *gin.Context, lookups []SummaryStatusLookup) ([]resolvedSummaryStatusLookup, error) {
	phoneNumbers, err := getUserPhoneNumbersFromContext(c)
	if err != nil {
		return nil, err
	}

	if len(phoneNumbers) == 0 {
		return []resolvedSummaryStatusLookup{}, nil
	}

	resolved := make([]resolvedSummaryStatusLookup, 0, len(lookups))
	for _, lookup := range lookups {
		resolvedUniqueID, ok, err := resolveAuthorizedUniqueID(lookup.UniqueID, lookup.LinkedID, phoneNumbers)
		if err != nil {
			return nil, err
		}

		entry := resolvedSummaryStatusLookup{
			UniqueID:         lookup.UniqueID,
			LinkedID:         lookup.LinkedID,
			ResolvedUniqueID: resolvedUniqueID,
		}
		if !ok {
			entry.ResolvedUniqueID = ""
		}
		resolved = append(resolved, entry)
	}

	return resolved, nil
}

func collectResolvedUniqueIDs(lookups []resolvedSummaryStatusLookup) []string {
	collected := make([]string, 0, len(lookups))
	seen := make(map[string]struct{})

	for _, lookup := range lookups {
		if lookup.ResolvedUniqueID == "" {
			continue
		}
		if _, exists := seen[lookup.ResolvedUniqueID]; exists {
			continue
		}
		seen[lookup.ResolvedUniqueID] = struct{}{}
		collected = append(collected, lookup.ResolvedUniqueID)
	}

	return collected
}

func normalizeLookupIDs(lookupIDs []string) []string {
	cleaned := make([]string, 0, len(lookupIDs))
	seen := make(map[string]struct{})

	for _, id := range lookupIDs {
		for _, candidate := range strings.Split(id, ",") {
			value := strings.TrimSpace(candidate)
			if value == "" {
				continue
			}
			if _, exists := seen[value]; exists {
				continue
			}
			seen[value] = struct{}{}
			cleaned = append(cleaned, value)
		}
	}

	return cleaned
}

func fetchSummaryDrawerFromDB(uniqueID string, phoneNumbers []string, excludedSrcNums []string) (*SummaryDrawer, bool, error) {
	database := db.GetSatelliteDB()
	if database == nil {
		return nil, false, sql.ErrConnDone
	}

	queryCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	args := []interface{}{uniqueID}
	phoneStart := 2
	for _, phoneNumber := range phoneNumbers {
		args = append(args, phoneNumber)
	}

	excludeStart := phoneStart + len(phoneNumbers)
	for _, excludedSrcNum := range excludedSrcNums {
		args = append(args, excludedSrcNum)
	}

	orderBy := "updated_at DESC, id DESC"
	if len(phoneNumbers) > 0 {
		phonePlaceholders := buildPostgresPlaceholders(len(phoneNumbers), phoneStart)
		srcClause := fmt.Sprintf("(src_number IN (%s)) DESC", phonePlaceholders)
		dstClause := fmt.Sprintf("(dst_number IN (%s)) DESC", phonePlaceholders)
		if len(excludedSrcNums) > 0 {
			excludePlaceholders := buildPostgresPlaceholders(len(excludedSrcNums), excludeStart)
			notExcludedClause := fmt.Sprintf("(src_number NOT IN (%s)) DESC", excludePlaceholders)
			orderBy = srcClause + ", " + notExcludedClause + ", " + dstClause + ", " + orderBy
		} else {
			orderBy = srcClause + ", " + dstClause + ", " + orderBy
		}
	}

	query := fmt.Sprintf(`
		SELECT uniqueid, summary, sentiment, state, cleaned_transcription, raw_transcription, created_at, updated_at, deleted_at
		FROM transcripts
		WHERE uniqueid = $1 AND deleted_at IS NULL
		ORDER BY %s
		LIMIT 1`, orderBy)

	var (
		dbUniqueID  string
		dbSummary   sql.NullString
		dbSentiment sql.NullInt16
		dbState     string
		dbCleaned   sql.NullString
		dbRaw       sql.NullString
		dbCreatedAt time.Time
		dbUpdatedAt time.Time
		dbDeletedAt sql.NullTime
	)

	if err := database.QueryRowContext(queryCtx, query, args...).Scan(
		&dbUniqueID,
		&dbSummary,
		&dbSentiment,
		&dbState,
		&dbCleaned,
		&dbRaw,
		&dbCreatedAt,
		&dbUpdatedAt,
		&dbDeletedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, err
	}

	if !dbSummary.Valid || strings.TrimSpace(dbSummary.String) == "" {
		return nil, false, nil
	}

	if dbDeletedAt.Valid {
		return nil, false, nil
	}

	var sentiment *int
	if dbSentiment.Valid {
		value := int(dbSentiment.Int16)
		sentiment = &value
	}

	var deletedAt *time.Time
	if dbDeletedAt.Valid {
		value := dbDeletedAt.Time
		deletedAt = &value
	}

	callMeta, err := fetchSummaryCDRFields(uniqueID)
	if err != nil {
		return nil, false, err
	}
	callTimestamp := alignCallTimestampLocation(callMeta.CallTimestamp, &dbCreatedAt)

	return &SummaryDrawer{
		UniqueID:      dbUniqueID,
		Summary:       strings.TrimSpace(dbSummary.String),
		Sentiment:     sentiment,
		State:         dbState,
		Src:           callMeta.Src,
		Dst:           callMeta.Dst,
		CNam:          callMeta.CNam,
		Company:       callMeta.Company,
		DstCompany:    callMeta.DstCompany,
		DstCNam:       callMeta.DstCNam,
		CallTimestamp: callTimestamp,
		CreatedAt:     dbCreatedAt,
		UpdatedAt:     dbUpdatedAt,
		DeletedAt:     deletedAt,
	}, true, nil
}

func fetchSummaryListFromDB(uniqueIDs []string) ([]SummaryListItem, error) {
	if len(uniqueIDs) == 0 {
		return []SummaryListItem{}, nil
	}

	database := db.GetSatelliteDB()
	if database == nil {
		return nil, sql.ErrConnDone
	}

	queryCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	placeholders := buildPostgresPlaceholders(len(uniqueIDs), 1)
	query := fmt.Sprintf(`
		SELECT DISTINCT ON (uniqueid) uniqueid, cleaned_transcription, raw_transcription, summary, state, updated_at
		FROM transcripts
		WHERE deleted_at IS NULL AND uniqueid IN (%s)
		ORDER BY uniqueid, updated_at DESC, id DESC`, placeholders)

	args := make([]interface{}, 0, len(uniqueIDs))
	for _, id := range uniqueIDs {
		args = append(args, id)
	}

	rows, err := database.QueryContext(queryCtx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]SummaryListItem, 0)
	for rows.Next() {
		var (
			dbUniqueID  string
			dbCleaned   sql.NullString
			dbRaw       sql.NullString
			dbSummary   sql.NullString
			dbState     string
			dbUpdatedAt time.Time
		)

		if err := rows.Scan(&dbUniqueID, &dbCleaned, &dbRaw, &dbSummary, &dbState, &dbUpdatedAt); err != nil {
			return nil, err
		}

		hasTranscription := false
		if dbCleaned.Valid && strings.TrimSpace(dbCleaned.String) != "" {
			hasTranscription = true
		} else if dbRaw.Valid && strings.TrimSpace(dbRaw.String) != "" {
			hasTranscription = true
		}

		hasSummary := dbSummary.Valid && strings.TrimSpace(dbSummary.String) != ""

		updatedAt := dbUpdatedAt
		items = append(items, SummaryListItem{
			UniqueID:         dbUniqueID,
			State:            dbState,
			HasTranscription: hasTranscription,
			HasSummary:       hasSummary,
			UpdatedAt:        &updatedAt,
		})
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return items, nil
}

func fetchSummaryStateFromDB(uniqueID string) (string, bool, bool, bool, error) {
	database := db.GetSatelliteDB()
	if database == nil {
		return "", false, false, false, sql.ErrConnDone
	}

	queryCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var (
		state     sql.NullString
		summary   sql.NullString
		cleaned   sql.NullString
		raw       sql.NullString
		deletedAt sql.NullTime
	)

	query := "SELECT state, summary, cleaned_transcription, raw_transcription, deleted_at FROM transcripts WHERE uniqueid = $1 AND deleted_at IS NULL ORDER BY updated_at DESC, id DESC LIMIT 1"
	if err := database.QueryRowContext(queryCtx, query, uniqueID).Scan(&state, &summary, &cleaned, &raw, &deletedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", false, false, false, nil
		}
		return "", false, false, false, err
	}

	if deletedAt.Valid {
		return "", false, false, false, nil
	}

	cleanState := strings.TrimSpace(state.String)
	hasSummary := summary.Valid && strings.TrimSpace(summary.String) != ""
	hasTranscription := (cleaned.Valid && strings.TrimSpace(cleaned.String) != "") ||
		(raw.Valid && strings.TrimSpace(raw.String) != "")

	return cleanState, hasSummary, hasTranscription, true, nil
}

func fetchSummaryFromDB(uniqueID string) (string, bool, error) {
	database := db.GetSatelliteDB()
	if database == nil {
		return "", false, sql.ErrConnDone
	}

	queryCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var summaryText sql.NullString
	query := "SELECT summary FROM transcripts WHERE uniqueid = $1 AND deleted_at IS NULL ORDER BY updated_at DESC, id DESC LIMIT 1"
	err := database.QueryRowContext(queryCtx, query, uniqueID).Scan(&summaryText)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", false, nil
		}
		return "", false, err
	}

	if !summaryText.Valid || strings.TrimSpace(summaryText.String) == "" {
		return "", false, nil
	}

	return summaryText.String, true, nil
}

func updateSummaryInDB(uniqueID, summaryText string) (bool, error) {
	database := db.GetSatelliteDB()
	if database == nil {
		return false, sql.ErrConnDone
	}

	queryCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	query := `
		WITH canonical AS (
			SELECT id FROM transcripts WHERE uniqueid = $2 AND deleted_at IS NULL ORDER BY updated_at DESC, id DESC LIMIT 1
		)
		UPDATE transcripts SET summary = $1 WHERE id IN (SELECT id FROM canonical)`
	result, err := database.ExecContext(queryCtx, query, summaryText, uniqueID)
	if err != nil {
		return false, err
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return false, err
	}

	return affected > 0, nil
}

func deleteSummaryInDB(uniqueID string) (bool, error) {
	database := db.GetSatelliteDB()
	if database == nil {
		return false, sql.ErrConnDone
	}

	queryCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	query := "UPDATE transcripts SET deleted_at = NOW() WHERE uniqueid = $1 AND deleted_at IS NULL"
	result, err := database.ExecContext(queryCtx, query, uniqueID)
	if err != nil {
		return false, err
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return false, err
	}

	return affected > 0, nil
}

func fetchSummaryCDRFields(uniqueID string) (*CallMetadata, error) {
	database := db.GetCDRDB()
	if database == nil {
		return nil, sql.ErrConnDone
	}

	queryCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	callMeta, err := fetchCallMetadataFromCDR(queryCtx, database, uniqueID)
	if err != nil {
		return nil, err
	}
	return callMeta, nil
}

func fetchCallMetadataFromCDR(queryCtx context.Context, database *sql.DB, uniqueID string) (*CallMetadata, error) {
	var (
		src        sql.NullString
		dst        sql.NullString
		cnam       sql.NullString
		company    sql.NullString
		dstCompany sql.NullString
		dstCNam    sql.NullString
		callDate   sql.NullTime
	)

	query := "SELECT src, dst, cnam, company, dst_company, dst_cnam, calldate FROM cdr WHERE uniqueid = ? ORDER BY calldate DESC LIMIT 1"
	err := database.QueryRowContext(queryCtx, query, uniqueID).Scan(&src, &dst, &cnam, &company, &dstCompany, &dstCNam, &callDate)
	if err != nil && isMissingColumnError(err) {
		query = "SELECT src, dst, cnam, dst_cnam, calldate FROM cdr WHERE uniqueid = ? ORDER BY calldate DESC LIMIT 1"
		err = database.QueryRowContext(queryCtx, query, uniqueID).Scan(&src, &dst, &cnam, &dstCNam, &callDate)
	}
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return &CallMetadata{}, nil
		}
		return nil, err
	}

	var callTimestamp *time.Time
	if callDate.Valid {
		value := callDate.Time
		callTimestamp = &value
	}

	return &CallMetadata{
		Src:           strings.TrimSpace(src.String),
		Dst:           strings.TrimSpace(dst.String),
		CNam:          strings.TrimSpace(cnam.String),
		Company:       strings.TrimSpace(company.String),
		DstCompany:    strings.TrimSpace(dstCompany.String),
		DstCNam:       strings.TrimSpace(dstCNam.String),
		CallTimestamp: callTimestamp,
	}, nil
}

func isMissingColumnError(err error) bool {
	return strings.Contains(strings.ToLower(err.Error()), "unknown column")
}

func alignCallTimestampLocation(callTimestamp *time.Time, reference *time.Time) *time.Time {
	if callTimestamp == nil || reference == nil {
		return callTimestamp
	}

	value := time.Date(
		callTimestamp.Year(),
		callTimestamp.Month(),
		callTimestamp.Day(),
		callTimestamp.Hour(),
		callTimestamp.Minute(),
		callTimestamp.Second(),
		callTimestamp.Nanosecond(),
		reference.Location(),
	)

	return &value
}

func buildPostgresPlaceholders(count int, startIndex int) string {
	if count <= 0 {
		return ""
	}
	placeholders := make([]string, 0, count)
	for i := 0; i < count; i++ {
		placeholders = append(placeholders, fmt.Sprintf("$%d", startIndex+i))
	}
	return strings.Join(placeholders, ",")
}
