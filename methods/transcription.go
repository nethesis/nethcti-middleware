/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package methods

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"time"

	jwt "github.com/appleboy/gin-jwt/v3"
	"github.com/fatih/structs"
	"github.com/gin-gonic/gin"

	"github.com/nethesis/nethcti-middleware/db"
	"github.com/nethesis/nethcti-middleware/logs"
	"github.com/nethesis/nethcti-middleware/models"
	"github.com/nethesis/nethcti-middleware/store"
	"github.com/nethesis/nethcti-middleware/summary"
)

var (
	getUserInfoFunc                      = GetUserInfo
	fetchTranscriptionFunc               = fetchTranscriptionFromDB
	fetchTranscriptionMetaFunc           = fetchTranscriptionMetadataFromCDR
	checkUserParticipationFunc           = checkUserParticipationInCDR
	checkUserParticipationByLinkedIDFunc = checkUserParticipationByLinkedIDInCDR
)

var errUnauthorized = errors.New("unauthorized")

type TranscriptionDrawer struct {
	UniqueID      string     `json:"uniqueid"`
	Transcription string     `json:"transcription"`
	Src           string     `json:"src,omitempty"`
	CNum          string     `json:"cnum,omitempty"`
	CNam          string     `json:"cnam,omitempty"`
	Company       string     `json:"company,omitempty"`
	CCompany      string     `json:"ccompany,omitempty"`
	DstCompany    string     `json:"dst_company,omitempty"`
	DstCNam       string     `json:"dst_cnam,omitempty"`
	Dst           string     `json:"dst,omitempty"`
	CallTimestamp *time.Time `json:"call_timestamp,omitempty"`
	CreatedAt     *time.Time `json:"created_at"`
}

// GetTranscriptionByUniqueID returns the transcription for the given unique ID.
func GetTranscriptionByUniqueID(c *gin.Context) {
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
		logs.Log("[ERROR][TRANSCRIPTS] Failed to validate CDR participation for uniqueid " + uniqueID + ": " + err.Error())
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

	transcription, createdAt, found, err := fetchTranscriptionFunc(uniqueID)
	if err != nil {
		logs.Log("[ERROR][TRANSCRIPTS] Failed to fetch transcription for uniqueid " + uniqueID + ": " + err.Error())
		c.JSON(http.StatusInternalServerError, structs.Map(models.StatusInternalServerError{
			Code:    http.StatusInternalServerError,
			Message: "failed to fetch transcription",
			Data:    nil,
		}))
		return
	}

	if !found {
		c.JSON(http.StatusNotFound, structs.Map(models.StatusNotFound{
			Code:    http.StatusNotFound,
			Message: "transcription not found",
			Data:    nil,
		}))
		return
	}

	callMeta, err := fetchTranscriptionMetaFunc(uniqueID)
	if err != nil {
		logs.Log("[ERROR][TRANSCRIPTS] Failed to fetch CDR metadata for uniqueid " + uniqueID + ": " + err.Error())
		c.JSON(http.StatusServiceUnavailable, structs.Map(models.StatusServiceUnavailable{
			Code:    http.StatusServiceUnavailable,
			Message: "cdr database unavailable",
			Data:    nil,
		}))
		return
	}

	c.JSON(http.StatusOK, structs.Map(models.StatusOK{
		Code:    http.StatusOK,
		Message: "success",
		Data: gin.H{
			"uniqueid":       uniqueID,
			"transcription":  transcription,
			"src":            callMeta.Src,
			"cnum":           callMeta.Src,
			"cnam":           callMeta.CNam,
			"company":        callMeta.Company,
			"ccompany":       callMeta.Company,
			"dst_company":    callMeta.DstCompany,
			"dst_cnam":       callMeta.DstCNam,
			"dst":            callMeta.Dst,
			"call_timestamp": alignCallTimestampLocation(callMeta.CallTimestamp, createdAt),
			"created_at":     createdAt,
		},
	}))
}

func ensureUserParticipatedInCall(c *gin.Context, uniqueID string) (bool, error) {
	username, err := getUsernameFromContext(c)
	if err != nil {
		return false, err
	}

	userSession := store.UserSessions[username]
	if userSession == nil || strings.TrimSpace(userSession.NethCTIToken) == "" {
		logs.Log("[WARNING][TRANSCRIPTS] Missing user session or token for user " + username + " (uniqueid: " + uniqueID + ")")
		return false, errUnauthorized
	}

	userInfo, err := getUserInfoFunc(userSession.NethCTIToken)
	if err != nil {
		logs.Log("[ERROR][TRANSCRIPTS] Failed to load user info for user " + username + " (uniqueid: " + uniqueID + "): " + err.Error())
		return false, err
	}

	if len(userInfo.PhoneNumbers) == 0 {
		logs.Log("[WARNING][TRANSCRIPTS] No phone numbers for user " + username + " (uniqueid: " + uniqueID + ")")
		return false, nil
	}

	return checkUserParticipationFunc(uniqueID, userInfo.PhoneNumbers)
}

func logForbiddenParticipation(c *gin.Context, uniqueID string) {
	username, err := getUsernameFromContext(c)
	if err != nil {
		logs.Log("[WARNING][TRANSCRIPTS] Forbidden participation check without valid user (uniqueid: " + uniqueID + ")")
		return
	}

	userSession := store.UserSessions[username]
	if userSession == nil || strings.TrimSpace(userSession.NethCTIToken) == "" {
		logs.Log("[WARNING][TRANSCRIPTS] Forbidden participation: missing session for user " + username + " (uniqueid: " + uniqueID + ")")
		return
	}

	userInfo, err := getUserInfoFunc(userSession.NethCTIToken)
	if err != nil {
		logs.Log("[WARNING][TRANSCRIPTS] Forbidden participation: failed to load user info for user " + username + " (uniqueid: " + uniqueID + "): " + err.Error())
		return
	}

	logs.Log("[INFO][TRANSCRIPTS] Forbidden participation: user " + username + " (uniqueid: " + uniqueID + ") numbers: " + strings.Join(userInfo.PhoneNumbers, ", "))
}

func getUsernameFromContext(c *gin.Context) (string, error) {
	claims := jwt.ExtractClaims(c)
	username, ok := claims["id"].(string)
	if !ok || username == "" {
		return "", errUnauthorized
	}
	return username, nil
}

func fetchTranscriptionFromDB(uniqueID string) (string, *time.Time, bool, error) {
	database := db.GetSatelliteDB()
	if database == nil {
		return "", nil, false, sql.ErrConnDone
	}

	queryCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var cleaned sql.NullString
	var raw sql.NullString
	var createdAt sql.NullTime
	query := "SELECT cleaned_transcription, raw_transcription, created_at FROM transcripts WHERE uniqueid = $1 LIMIT 1"
	err := database.QueryRowContext(queryCtx, query, uniqueID).Scan(&cleaned, &raw, &createdAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", nil, false, nil
		}
		return "", nil, false, err
	}

	var createdAtPtr *time.Time
	if createdAt.Valid {
		createdAtPtr = &createdAt.Time
	}

	if cleaned.Valid {
		cleanedText := strings.TrimSpace(cleaned.String)
		if cleanedText != "" {
			return cleanedText, createdAtPtr, true, nil
		}
	}

	if raw.Valid {
		rawText := strings.TrimSpace(raw.String)
		if rawText != "" {
			return rawText, createdAtPtr, true, nil
		}
	}

	return "", createdAtPtr, false, nil
}

func fetchTranscriptionMetadataFromCDR(uniqueID string) (*CallMetadata, error) {
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

func checkUserParticipationInCDR(uniqueID string, phoneNumbers []string) (bool, error) {
	if uniqueID == "" || len(phoneNumbers) == 0 {
		return false, nil
	}

	database := db.GetCDRDB()
	if database == nil {
		return false, sql.ErrConnDone
	}

	phoneSet := make(map[string]struct{}, len(phoneNumbers))
	for _, number := range phoneNumbers {
		cleaned := strings.TrimSpace(number)
		if cleaned != "" {
			phoneSet[cleaned] = struct{}{}
		}
	}
	if len(phoneSet) == 0 {
		return false, nil
	}

	queryCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rows, err := database.QueryContext(queryCtx, "SELECT src, dst FROM cdr WHERE uniqueid = ?", uniqueID)
	if err != nil {
		return false, err
	}
	defer rows.Close()

	for rows.Next() {
		var src, dst sql.NullString
		if err := rows.Scan(&src, &dst); err != nil {
			return false, err
		}

		if src.Valid {
			if _, ok := phoneSet[strings.TrimSpace(src.String)]; ok {
				return true, nil
			}
		}

		if dst.Valid {
			if _, ok := phoneSet[strings.TrimSpace(dst.String)]; ok {
				return true, nil
			}
		}
	}

	if err := rows.Err(); err != nil {
		return false, err
	}

	return false, nil
}

// checkUserParticipationByLinkedIDInCDR checks whether any leg of the call chain
// identified by linkedID has the user's phone number as src or dst. This is the
// correct check for transferred calls and queue calls, where multiple CDR rows
// share the same linkedid.
func checkUserParticipationByLinkedIDInCDR(linkedID string, phoneNumbers []string) (bool, error) {
	if linkedID == "" || len(phoneNumbers) == 0 {
		return false, nil
	}

	database := db.GetCDRDB()
	if database == nil {
		return false, sql.ErrConnDone
	}

	phoneSet := make(map[string]struct{}, len(phoneNumbers))
	for _, number := range phoneNumbers {
		cleaned := strings.TrimSpace(number)
		if cleaned != "" {
			phoneSet[cleaned] = struct{}{}
		}
	}
	if len(phoneSet) == 0 {
		return false, nil
	}

	queryCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rows, err := database.QueryContext(queryCtx, "SELECT src, dst FROM cdr WHERE linkedid = ?", linkedID)
	if err != nil {
		return false, err
	}
	defer rows.Close()

	for rows.Next() {
		var src, dst sql.NullString
		if err := rows.Scan(&src, &dst); err != nil {
			return false, err
		}

		if src.Valid {
			if _, ok := phoneSet[strings.TrimSpace(src.String)]; ok {
				return true, nil
			}
		}

		if dst.Valid {
			if _, ok := phoneSet[strings.TrimSpace(dst.String)]; ok {
				return true, nil
			}
		}
	}

	if err := rows.Err(); err != nil {
		return false, err
	}

	return false, nil
}

// ensureUserParticipatedInCallChain checks participation across all CDR legs
// sharing the same linkedID, which is needed for transfers and queue calls.
func ensureUserParticipatedInCallChain(c *gin.Context, linkedID string) (bool, error) {
	username, err := getUsernameFromContext(c)
	if err != nil {
		return false, err
	}

	userSession := store.UserSessions[username]
	if userSession == nil || strings.TrimSpace(userSession.NethCTIToken) == "" {
		logs.Log("[WARNING][TRANSCRIPTS] Missing user session or token for user " + username + " (linkedid: " + linkedID + ")")
		return false, errUnauthorized
	}

	userInfo, err := getUserInfoFunc(userSession.NethCTIToken)
	if err != nil {
		logs.Log("[ERROR][TRANSCRIPTS] Failed to load user info for user " + username + " (linkedid: " + linkedID + "): " + err.Error())
		return false, err
	}

	if len(userInfo.PhoneNumbers) == 0 {
		logs.Log("[WARNING][TRANSCRIPTS] No phone numbers for user " + username + " (linkedid: " + linkedID + ")")
		return false, nil
	}

	return checkUserParticipationByLinkedIDFunc(linkedID, userInfo.PhoneNumbers)
}
