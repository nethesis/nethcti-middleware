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
	resolveLinkedIDToUniqueIDFunc        = resolveUniqueIDByLinkedIDForUserInCDR
	discoverLinkedIDFromCDRFunc          = discoverLinkedIDFromCDR
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

// GetTranscriptionByUniqueID returns the transcription for the given uniqueid.
func GetTranscriptionByUniqueID(c *gin.Context) {
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

	uniqueID, ok, err := ensureUserParticipatedInCall(c, uniqueIDHint, linkedID)
	if err != nil {
		if errors.Is(err, errUnauthorized) {
			c.JSON(http.StatusUnauthorized, structs.Map(models.StatusUnauthorized{
				Code:    http.StatusUnauthorized,
				Message: "unauthorized",
				Data:    nil,
			}))
			return
		}
		logs.Log("[ERROR][TRANSCRIPTS] Failed to validate CDR participation for uniqueid " + uniqueIDHint + ": " + err.Error())
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

func getLinkedIDFromQuery(c *gin.Context) string {
	return strings.TrimSpace(c.Query("linkedid"))
}

func getUserPhoneNumbersFromContext(c *gin.Context) ([]string, error) {
	username, err := getUsernameFromContext(c)
	if err != nil {
		return nil, err
	}

	userSession := store.UserSessions[username]
	if userSession == nil || strings.TrimSpace(userSession.NethCTIToken) == "" {
		logs.Log("[WARNING][TRANSCRIPTS] Missing user session or token for user " + username)
		return nil, errUnauthorized
	}

	userInfo, err := getUserInfoFunc(userSession.NethCTIToken)
	if err != nil {
		logs.Log("[ERROR][TRANSCRIPTS] Failed to load user info for user " + username + ": " + err.Error())
		return nil, err
	}

	return userInfo.PhoneNumbers, nil
}

func resolveAuthorizedUniqueID(uniqueID string, linkedID string, phoneNumbers []string) (string, bool, error) {
	if len(phoneNumbers) == 0 {
		return "", false, nil
	}

	// If linkedID not provided by client, try to discover it from CDR.
	// This handles older clients and queue/transfer calls where the frontend
	// only knows the initial leg's uniqueID, not the shared linkedID.
	if linkedID == "" && uniqueID != "" {
		discovered, err := discoverLinkedIDFromCDRFunc(uniqueID)
		if err != nil {
			return "", false, err
		}
		if discovered != "" {
			linkedID = discovered
		}
	}

	if linkedID != "" {
		ok, err := checkUserParticipationByLinkedIDFunc(linkedID, phoneNumbers)
		if err != nil {
			return "", false, err
		}
		if ok {
			resolvedUniqueID, err := resolveLinkedIDToUniqueIDFunc(linkedID, phoneNumbers)
			if err != nil {
				return "", false, err
			}
			if resolvedUniqueID != "" {
				return resolvedUniqueID, true, nil
			}
			if uniqueID != "" {
				return uniqueID, true, nil
			}
			return "", true, nil
		}
	}

	if uniqueID == "" {
		return "", false, nil
	}

	ok, err := checkUserParticipationFunc(uniqueID, phoneNumbers)
	if err != nil {
		return "", false, err
	}
	if !ok {
		return "", false, nil
	}

	return uniqueID, true, nil
}

func ensureUserParticipatedInCall(c *gin.Context, uniqueID string, linkedID string) (string, bool, error) {
	phoneNumbers, err := getUserPhoneNumbersFromContext(c)
	if err != nil {
		return "", false, err
	}

	if len(phoneNumbers) == 0 {
		username, _ := getUsernameFromContext(c)
		logs.Log("[WARNING][TRANSCRIPTS] No phone numbers for user " + username + " (uniqueid: " + uniqueID + ", linkedid: " + linkedID + ")")
		return "", false, nil
	}

	return resolveAuthorizedUniqueID(uniqueID, linkedID, phoneNumbers)
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
	query := "SELECT cleaned_transcription, raw_transcription, created_at FROM transcripts WHERE uniqueid = $1 AND deleted_at IS NULL ORDER BY updated_at DESC, id DESC LIMIT 1"
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

	rows, err := database.QueryContext(queryCtx, "SELECT src, dst, cnum FROM cdr WHERE uniqueid = ?", uniqueID)
	if err != nil {
		return false, err
	}
	defer rows.Close()

	for rows.Next() {
		var src, dst, cnum sql.NullString
		if err := rows.Scan(&src, &dst, &cnum); err != nil {
			return false, err
		}

		for _, val := range []sql.NullString{src, dst, cnum} {
			if val.Valid {
				if _, ok := phoneSet[strings.TrimSpace(val.String)]; ok {
					return true, nil
				}
			}
		}
	}

	if err := rows.Err(); err != nil {
		return false, err
	}

	return false, nil
}

// checkUserParticipationByLinkedIDInCDR checks whether any leg of the call chain
// identified by linkedID has the user's phone number as src, dst, or cnum. This is the
// correct check for transferred calls and queue calls, where multiple CDR rows
// share the same linkedid. cnum is also checked to handle outbound calls where src
// contains the trunk CallerID instead of the originating extension.
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

	rows, err := database.QueryContext(queryCtx, "SELECT src, dst, cnum FROM cdr WHERE linkedid = ?", linkedID)
	if err != nil {
		return false, err
	}
	defer rows.Close()

	for rows.Next() {
		var src, dst, cnum sql.NullString
		if err := rows.Scan(&src, &dst, &cnum); err != nil {
			return false, err
		}

		for _, val := range []sql.NullString{src, dst, cnum} {
			if val.Valid {
				if _, ok := phoneSet[strings.TrimSpace(val.String)]; ok {
					return true, nil
				}
			}
		}
	}

	if err := rows.Err(); err != nil {
		return false, err
	}

	return false, nil
}

func resolveUniqueIDByLinkedIDForUserInCDR(linkedID string, phoneNumbers []string) (string, error) {
	if linkedID == "" || len(phoneNumbers) == 0 {
		return "", nil
	}

	database := db.GetCDRDB()
	if database == nil {
		return "", sql.ErrConnDone
	}

	phoneSet := make(map[string]struct{}, len(phoneNumbers))
	for _, number := range phoneNumbers {
		cleaned := strings.TrimSpace(number)
		if cleaned != "" {
			phoneSet[cleaned] = struct{}{}
		}
	}
	if len(phoneSet) == 0 {
		return "", nil
	}

	queryCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rows, err := database.QueryContext(
		queryCtx,
		`SELECT uniqueid, src, dst, cnum
		 FROM cdr
		 WHERE linkedid = ?
		 ORDER BY CASE WHEN disposition = 'ANSWERED' THEN 0 ELSE 1 END, calldate DESC`,
		linkedID,
	)
	if err != nil {
		return "", err
	}
	defer rows.Close()

	for rows.Next() {
		var uniqueID string
		var src, dst, cnum sql.NullString
		if err := rows.Scan(&uniqueID, &src, &dst, &cnum); err != nil {
			return "", err
		}

		for _, val := range []sql.NullString{src, dst, cnum} {
			if val.Valid {
				if _, ok := phoneSet[strings.TrimSpace(val.String)]; ok {
					return uniqueID, nil
				}
			}
		}
	}

	if err := rows.Err(); err != nil {
		return "", err
	}

	return "", nil
}

// discoverLinkedIDFromCDR looks up the linkedid for a given uniqueid in the CDR.
// This is used as a fallback when the client did not provide a linkedid, allowing
// the middleware to find all legs of a multi-leg call (e.g., queue or transfer calls).
func discoverLinkedIDFromCDR(uniqueID string) (string, error) {
	if uniqueID == "" {
		return "", nil
	}

	database := db.GetCDRDB()
	if database == nil {
		return "", nil
	}

	queryCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var linkedID sql.NullString
	err := database.QueryRowContext(queryCtx, "SELECT linkedid FROM cdr WHERE uniqueid = ? LIMIT 1", uniqueID).Scan(&linkedID)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", nil
		}
		return "", err
	}

	if linkedID.Valid {
		return strings.TrimSpace(linkedID.String), nil
	}
	return "", nil
}
