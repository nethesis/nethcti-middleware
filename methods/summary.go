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
	DstCNam       string     `json:"dst_cnam,omitempty"`
	CallTimestamp *time.Time `json:"call_timestamp,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	DeletedAt     *time.Time `json:"deleted_at,omitempty"`
}

type SummaryListItem struct {
	UniqueID         string     `json:"uniqueid"`
	State            string     `json:"state"`
	HasTranscription bool       `json:"has_transcription"`
	HasSummary       bool       `json:"has_summary"`
	UpdatedAt        *time.Time `json:"updated_at"`
}

var (
	fetchSummaryDrawerFunc = fetchSummaryDrawerFromDB
	fetchSummaryListFunc   = fetchSummaryListFromDB
	fetchSummaryStateFunc  = fetchSummaryStateFromDB
	fetchSummaryFunc       = fetchSummaryFromDB
	updateSummaryFunc      = updateSummaryInDB
	deleteSummaryFunc      = deleteSummaryInDB
)

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

	uniqueID := strings.TrimSpace(req.UniqueID)
	if uniqueID == "" {
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

	started := summary.StartSummaryWatch(uniqueID)
	if !started {
		logs.Log("[INFO][SUMMARY] Watch already active or configuration missing for uniqueid: " + uniqueID)
		c.JSON(http.StatusOK, structs.Map(models.StatusOK{
			Code:    http.StatusOK,
			Message: "watch already active or unavailable",
			Data: gin.H{
				"uniqueid": uniqueID,
			},
		}))
		return
	}

	logs.Log("[INFO][SUMMARY] Watch started for uniqueid: " + uniqueID)
	c.JSON(http.StatusAccepted, structs.Map(models.StatusOK{
		Code:    http.StatusAccepted,
		Message: "watch started",
		Data: gin.H{
			"uniqueid": uniqueID,
		},
	}))
}

// CheckSummaryByUniqueID verifies whether a transcript row exists for the given unique ID.
// It is intended for HEAD endpoints and returns status only (no response body).
func CheckSummaryByUniqueID(c *gin.Context) {
	uniqueID := strings.TrimSpace(c.Param("uniqueid"))
	if uniqueID == "" {
		c.Status(http.StatusBadRequest)
		return
	}

	if !summary.IsSatelliteDBConfigured() {
		c.Status(http.StatusServiceUnavailable)
		return
	}

	if ok, err := ensureUserParticipatedInCall(c, uniqueID); err != nil {
		if errors.Is(err, errUnauthorized) {
			c.Status(http.StatusUnauthorized)
			return
		}
		logs.Log("[ERROR][SUMMARY] Failed to validate CDR participation for uniqueid " + uniqueID + ": " + err.Error())
		c.Status(http.StatusServiceUnavailable)
		return
	} else if !ok {
		logForbiddenParticipation(c, uniqueID)
		c.Status(http.StatusForbidden)
		return
	}

	_, _, exists, err := fetchSummaryStateFunc(uniqueID)
	if err != nil {
		logs.Log("[ERROR][SUMMARY] Failed to fetch summary for uniqueid " + uniqueID + ": " + err.Error())
		c.Status(http.StatusInternalServerError)
		return
	}

	if !exists {
		c.Status(http.StatusNotFound)
		return
	}

	c.Status(http.StatusOK)
}

// GetSummaryByUniqueID returns the summary for the given unique ID.
func GetSummaryByUniqueID(c *gin.Context) {
	uniqueID := strings.TrimSpace(c.Param("uniqueid"))
	if uniqueID == "" {
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

	if ok, err := ensureUserParticipatedInCall(c, uniqueID); err != nil {
		if errors.Is(err, errUnauthorized) {
			c.JSON(http.StatusUnauthorized, structs.Map(models.StatusUnauthorized{
				Code:    http.StatusUnauthorized,
				Message: "unauthorized",
				Data:    nil,
			}))
			return
		}
		logs.Log("[ERROR][SUMMARY] Failed to validate CDR participation for uniqueid " + uniqueID + ": " + err.Error())
		c.JSON(http.StatusServiceUnavailable, structs.Map(models.StatusServiceUnavailable{
			Code:    http.StatusServiceUnavailable,
			Message: "cdr database unavailable",
			Data:    nil,
		}))
		return
	} else if !ok {
		logForbiddenParticipation(c, uniqueID)
		c.JSON(http.StatusForbidden, structs.Map(models.StatusForbidden{
			Code:    http.StatusForbidden,
			Message: "forbidden: user not part of call",
			Data:    nil,
		}))
		return
	}

	details, found, err := fetchSummaryDrawerFunc(uniqueID)
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

// DeleteSummaryByUniqueID removes the summary for the given unique ID.
func DeleteSummaryByUniqueID(c *gin.Context) {
	uniqueID := strings.TrimSpace(c.Param("uniqueid"))
	if uniqueID == "" {
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

	if ok, err := ensureUserParticipatedInCall(c, uniqueID); err != nil {
		if errors.Is(err, errUnauthorized) {
			c.JSON(http.StatusUnauthorized, structs.Map(models.StatusUnauthorized{
				Code:    http.StatusUnauthorized,
				Message: "unauthorized",
				Data:    nil,
			}))
			return
		}
		logs.Log("[ERROR][SUMMARY] Failed to validate CDR participation for uniqueid " + uniqueID + ": " + err.Error())
		c.JSON(http.StatusServiceUnavailable, structs.Map(models.StatusServiceUnavailable{
			Code:    http.StatusServiceUnavailable,
			Message: "cdr database unavailable",
			Data:    nil,
		}))
		return
	} else if !ok {
		logForbiddenParticipation(c, uniqueID)
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

// UpdateSummaryByUniqueID updates the summary for the given unique ID.
func UpdateSummaryByUniqueID(c *gin.Context) {
	uniqueID := strings.TrimSpace(c.Param("uniqueid"))
	if uniqueID == "" {
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

	if ok, err := ensureUserParticipatedInCall(c, uniqueID); err != nil {
		if errors.Is(err, errUnauthorized) {
			c.JSON(http.StatusUnauthorized, structs.Map(models.StatusUnauthorized{
				Code:    http.StatusUnauthorized,
				Message: "unauthorized",
				Data:    nil,
			}))
			return
		}
		logs.Log("[ERROR][SUMMARY] Failed to validate CDR participation for uniqueid " + uniqueID + ": " + err.Error())
		c.JSON(http.StatusServiceUnavailable, structs.Map(models.StatusServiceUnavailable{
			Code:    http.StatusServiceUnavailable,
			Message: "cdr database unavailable",
			Data:    nil,
		}))
		return
	} else if !ok {
		logForbiddenParticipation(c, uniqueID)
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

	uniqueIDs, err := extractSummaryStatusUniqueIDs(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, structs.Map(models.StatusBadRequest{
			Code:    http.StatusBadRequest,
			Message: "invalid request payload",
			Data:    err.Error(),
		}))
		return
	}

	if len(uniqueIDs) == 0 {
		c.JSON(http.StatusBadRequest, structs.Map(models.StatusBadRequest{
			Code:    http.StatusBadRequest,
			Message: "uniqueids is required",
			Data:    nil,
		}))
		return
	}

	items, err := fetchSummaryListFunc(uniqueIDs)
	if err != nil {
		logs.Log("[ERROR][SUMMARY] Failed to list summaries: " + err.Error())
		c.JSON(http.StatusInternalServerError, structs.Map(models.StatusInternalServerError{
			Code:    http.StatusInternalServerError,
			Message: "failed to list summaries",
			Data:    nil,
		}))
		return
	}

	itemByID := make(map[string]SummaryListItem, len(items))
	for _, item := range items {
		itemByID[item.UniqueID] = item
	}

	result := make([]interface{}, 0, len(uniqueIDs))
	for _, id := range uniqueIDs {
		if item, ok := itemByID[id]; ok {
			result = append(result, item)
			continue
		}
		result = append(result, gin.H{
			"uniqueid": id,
			"error":    "not_found",
		})
	}

	c.JSON(http.StatusOK, structs.Map(models.StatusOK{
		Code:    http.StatusOK,
		Message: "success",
		Data:    result,
	}))
}

func extractSummaryStatusUniqueIDs(c *gin.Context) ([]string, error) {
	var req struct {
		UniqueIDs []string `json:"uniqueids"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		return nil, err
	}

	return normalizeUniqueIDs(req.UniqueIDs), nil
}

func normalizeUniqueIDs(uniqueIDs []string) []string {
	cleaned := make([]string, 0, len(uniqueIDs))
	seen := make(map[string]struct{})

	for _, id := range uniqueIDs {
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

func fetchSummaryDrawerFromDB(uniqueID string) (*SummaryDrawer, bool, error) {
	database := db.GetSatelliteDB()
	if database == nil {
		return nil, false, sql.ErrConnDone
	}

	queryCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	query := `
		SELECT uniqueid, summary, sentiment, state, cleaned_transcription, raw_transcription, created_at, updated_at, deleted_at
		FROM transcripts
		WHERE uniqueid = $1
		LIMIT 1`

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

	if err := database.QueryRowContext(queryCtx, query, uniqueID).Scan(
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

	src, dst, cnam, dstCNam, callTimestamp, err := fetchSummaryCDRFields(uniqueID)
	if err != nil {
		return nil, false, err
	}
	if callTimestamp != nil {
		value := time.Date(
			callTimestamp.Year(),
			callTimestamp.Month(),
			callTimestamp.Day(),
			callTimestamp.Hour(),
			callTimestamp.Minute(),
			callTimestamp.Second(),
			callTimestamp.Nanosecond(),
			dbCreatedAt.Location(),
		)
		callTimestamp = &value
	}

	return &SummaryDrawer{
		UniqueID:      dbUniqueID,
		Summary:       strings.TrimSpace(dbSummary.String),
		Sentiment:     sentiment,
		State:         dbState,
		Src:           src,
		Dst:           dst,
		CNam:          cnam,
		DstCNam:       dstCNam,
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
		SELECT uniqueid, cleaned_transcription, raw_transcription, summary, state, updated_at
		FROM transcripts
		WHERE deleted_at IS NULL AND uniqueid IN (%s)
		ORDER BY updated_at DESC`, placeholders)

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

func fetchSummaryStateFromDB(uniqueID string) (string, bool, bool, error) {
	database := db.GetSatelliteDB()
	if database == nil {
		return "", false, false, sql.ErrConnDone
	}

	queryCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var (
		state     sql.NullString
		summary   sql.NullString
		deletedAt sql.NullTime
	)

	query := "SELECT state, summary, deleted_at FROM transcripts WHERE uniqueid = $1 LIMIT 1"
	if err := database.QueryRowContext(queryCtx, query, uniqueID).Scan(&state, &summary, &deletedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", false, false, nil
		}
		return "", false, false, err
	}

	if deletedAt.Valid {
		return "", false, false, nil
	}

	cleanState := strings.TrimSpace(state.String)
	hasSummary := summary.Valid && strings.TrimSpace(summary.String) != ""

	return cleanState, hasSummary, true, nil
}

func fetchSummaryFromDB(uniqueID string) (string, bool, error) {
	database := db.GetSatelliteDB()
	if database == nil {
		return "", false, sql.ErrConnDone
	}

	queryCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var summaryText sql.NullString
	query := "SELECT summary FROM transcripts WHERE uniqueid = $1 LIMIT 1"
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

	query := "UPDATE transcripts SET summary = $1 WHERE uniqueid = $2"
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

	query := "UPDATE transcripts SET deleted_at = NOW() WHERE uniqueid = $1"
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

func fetchSummaryCDRFields(uniqueID string) (string, string, string, string, *time.Time, error) {
	database := db.GetCDRDB()
	if database == nil {
		return "", "", "", "", nil, sql.ErrConnDone
	}

	queryCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var (
		src      sql.NullString
		dst      sql.NullString
		cnam     sql.NullString
		dstCNam  sql.NullString
		callDate sql.NullTime
	)

	query := "SELECT src, dst, cnam, dst_cnam, calldate FROM cdr WHERE uniqueid = ? LIMIT 1"
	if err := database.QueryRowContext(queryCtx, query, uniqueID).Scan(&src, &dst, &cnam, &dstCNam, &callDate); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", "", "", "", nil, nil
		}
		return "", "", "", "", nil, err
	}

	var callTimestamp *time.Time
	if callDate.Valid {
		value := callDate.Time
		callTimestamp = &value
	}

	return strings.TrimSpace(src.String), strings.TrimSpace(dst.String), strings.TrimSpace(cnam.String), strings.TrimSpace(dstCNam.String), callTimestamp, nil
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
