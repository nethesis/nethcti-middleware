/*
 * Copyright (C) 2026 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package methods

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	jwt "github.com/appleboy/gin-jwt/v3"
	"github.com/fatih/structs"
	"github.com/gin-gonic/gin"

	"github.com/nethesis/nethcti-middleware/logs"
	"github.com/nethesis/nethcti-middleware/models"
	"github.com/nethesis/nethcti-middleware/store"
)

const (
	legacyVoicemailAllRows    = uint64(10000000000000)
	legacyQueryParameterLimit = 1000
)

type legacyVoicemailList struct {
	missingUser bool
	noVoicemail bool
	count       int64
	rows        []store.VoicemailMessageRow
}

var (
	countVoicemailMessagesFunc = store.CountLegacyVoicemailMessages
	listVoicemailMessagesFunc  = store.ListLegacyVoicemailMessages
	proxyV1RequestFunc         = ProxyV1Request

	qsDotNotation = regexp.MustCompile(`\.([^.[]+)`)
	qsBrackets    = regexp.MustCompile(`\[[^[\]]*\]`)
)

// ListVoicemailByID returns a single voicemail by DB id when :id is numeric,
// otherwise it lists the user's voicemail messages of the :id folder type.
func ListVoicemailByID(c *gin.Context) {
	rawID := c.Param("id")
	voicemailID := strings.TrimSpace(rawID)
	if voicemailID == "" {
		c.JSON(http.StatusBadRequest, structs.Map(models.StatusBadRequest{
			Code:    http.StatusBadRequest,
			Message: "voicemail id is required",
			Data:    nil,
		}))
		return
	}

	if !isNumericVoicemailID(voicemailID) {
		listLegacyVoicemailMessages(c, rawID)
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

	list, err := fetchLegacyVoicemailList(c, username, "all", nil, nil)
	if err == nil && (list.missingUser || list.noVoicemail) {
		err = errors.New("user has no single voicemail")
	}
	if err != nil {
		logs.Log("[ERROR][VOICEMAIL] Failed to fetch voicemail list for user " + username + ": " + err.Error())
		c.JSON(http.StatusBadGateway, gin.H{
			"code":    http.StatusBadGateway,
			"message": "failed to fetch voicemail list",
			"data":    nil,
		})
		return
	}

	filteredRows := make([]map[string]interface{}, 0, 1)
	for _, row := range list.rows {
		if strconv.FormatInt(row.ID, 10) == voicemailID {
			filteredRows = append(filteredRows, legacyVoicemailRowMap(row))
			break
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"count": len(filteredRows),
		"rows":  filteredRows,
	})
}

func listLegacyVoicemailMessages(c *gin.Context, folder string) {
	if !utf8.ValidString(folder) {
		c.Data(http.StatusBadRequest, "application/json; charset=utf-8", []byte(`{"code":"BadRequestError","message":"URI malformed"}`))
		return
	}

	offset, limit, ok := parseLegacyPagination(c.Request.URL.RawQuery)
	if !ok {
		proxyV1RequestFunc(c, c.Request.URL.Path, false)
		return
	}

	username, _ := jwt.ExtractClaims(c)["id"].(string)
	list, err := fetchLegacyVoicemailList(c, username, folder, offset, limit)
	if err != nil {
		logs.Log("[ERROR][VOICEMAIL] Failed to list voicemail messages for user " + username + ": " + err.Error())
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	if list.missingUser {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	if list.noVoicemail {
		c.Data(http.StatusOK, "application/json; charset=utf-8", []byte("[]"))
		return
	}

	c.Data(http.StatusOK, "application/json; charset=utf-8", encodeLegacyVoicemailList(list.count, list.rows))
}

func fetchLegacyVoicemailList(c *gin.Context, username, folderType string, offset, limit []string) (*legacyVoicemailList, error) {
	user, exists := loadLegacyUsersFunc()[username]
	if !exists {
		return &legacyVoicemailList{missingUser: true}, nil
	}
	voicemails := user.voicemails
	if len(voicemails) != 1 {
		return &legacyVoicemailList{noVoicemail: true}, nil
	}

	var folder *string
	if folderType != "all" {
		value, ok := decodeMySQLDoubleQuotedLiteral(folderType)
		if !ok {
			return nil, errors.New("voicemail type breaks the SQL string literal")
		}
		folder = &value
	}

	if hasSupplementaryRune(voicemails[0]) || (folder != nil && hasSupplementaryRune(*folder)) {
		return &legacyVoicemailList{rows: []store.VoicemailMessageRow{}}, nil
	}

	ctx := c.Request.Context()
	count, err := countVoicemailMessagesFunc(ctx, voicemails[0], folder)
	if err != nil {
		return nil, err
	}
	if count == 0 {
		return &legacyVoicemailList{rows: []store.VoicemailMessageRow{}}, nil
	}

	offsetValue := "0"
	if legacyParamTruthy(offset) {
		offsetValue = jsNumberToString(jsParseInt(strings.Join(offset, ",")))
	}
	limitValue := strconv.FormatUint(legacyVoicemailAllRows, 10)
	if legacyParamTruthy(limit) {
		limitValue = jsNumberToString(jsParseInt(strings.Join(limit, ",")))
	}

	offsetNumber, offsetOK := parseSQLLimitNumber(offsetValue)
	limitNumber, limitOK := parseSQLLimitNumber(limitValue)
	if !offsetOK || !limitOK {
		return nil, fmt.Errorf("invalid LIMIT %s, %s", offsetValue, limitValue)
	}

	rows, err := listVoicemailMessagesFunc(ctx, voicemails[0], folder, offsetNumber, limitNumber)
	if err != nil {
		return nil, err
	}

	return &legacyVoicemailList{count: count, rows: rows}, nil
}

func hasSupplementaryRune(value string) bool {
	for _, char := range value {
		if char > 0xffff {
			return true
		}
	}
	return false
}

func legacyParamTruthy(values []string) bool {
	return len(values) > 1 || (len(values) == 1 && values[0] != "")
}

func parseSQLLimitNumber(value string) (uint64, bool) {
	for _, char := range value {
		if char < '0' || char > '9' {
			return 0, false
		}
	}
	number, err := strconv.ParseUint(value, 10, 64)
	return number, err == nil
}

func parseLegacyPagination(rawQuery string) ([]string, []string, bool) {
	if rawQuery == "" {
		return nil, nil, true
	}

	parts := strings.SplitN(rawQuery, "&", legacyQueryParameterLimit+1)
	if len(parts) > legacyQueryParameterLimit {
		parts = parts[:legacyQueryParameterLimit]
	}

	var offset, limit []string
	for _, part := range parts {
		position := strings.Index(part, "]=")
		if position == -1 {
			position = strings.Index(part, "=")
		} else {
			position++
		}

		var key, value string
		if position == -1 {
			key = decodeQSComponent(part)
		} else {
			key = decodeQSComponent(part[:position])
			value = decodeQSComponent(part[position+1:])
		}

		switch key {
		case "offset":
			offset = append(offset, value)
			continue
		case "limit":
			limit = append(limit, value)
			continue
		case "":
			continue
		}

		expanded := qsDotNotation.ReplaceAllString(key, "[$1]")
		bracket := qsBrackets.FindStringIndex(expanded)
		if bracket == nil {
			continue
		}
		parent := expanded[:bracket[0]]
		if parent == "" || parent == "offset" || parent == "limit" {
			return nil, nil, false
		}
	}

	return offset, limit, true
}

func decodeQSComponent(value string) string {
	decoded, ok := jsDecodeURIComponent(strings.ReplaceAll(value, "+", " "))
	if !ok {
		return value
	}
	return decoded
}

func decodeMySQLDoubleQuotedLiteral(value string) (string, bool) {
	var builder strings.Builder
	for i := 0; i < len(value); {
		char, size := utf8.DecodeRuneInString(value[i:])
		switch char {
		case '\\':
			if i+size >= len(value) {
				return "", false
			}
			escaped, escapedSize := utf8.DecodeRuneInString(value[i+size:])
			switch escaped {
			case '0':
				builder.WriteByte(0)
			case 'b':
				builder.WriteByte('\b')
			case 'n':
				builder.WriteByte('\n')
			case 'r':
				builder.WriteByte('\r')
			case 't':
				builder.WriteByte('\t')
			case 'Z':
				builder.WriteByte(0x1a)
			case '%', '_':
				builder.WriteByte('\\')
				builder.WriteRune(escaped)
			default:
				builder.WriteRune(escaped)
			}
			i += size + escapedSize
		case '"':
			if i+1 < len(value) && value[i+1] == '"' {
				builder.WriteByte('"')
				i += 2
				continue
			}
			return "", false
		default:
			builder.WriteString(value[i : i+size])
			i += size
		}
	}
	return builder.String(), true
}

func legacyVoicemailStringValue(value sql.NullString) interface{} {
	if !value.Valid {
		return nil
	}
	return decodeUTF8LikeNode([]byte(value.String))
}

func legacyVoicemailRowMap(row store.VoicemailMessageRow) map[string]interface{} {
	return map[string]interface{}{
		"origtime":    legacyVoicemailStringValue(row.OrigTime),
		"duration":    legacyVoicemailStringValue(row.Duration),
		"id":          row.ID,
		"dir":         legacyVoicemailStringValue(row.Dir),
		"callerid":    legacyVoicemailStringValue(row.CallerID),
		"mailboxuser": legacyVoicemailStringValue(row.MailboxUser),
		"type":        legacyVoicemailStringValue(row.Type),
	}
}

func encodeLegacyVoicemailList(count int64, rows []store.VoicemailMessageRow) []byte {
	var buffer bytes.Buffer
	buffer.WriteString(`{"count":`)
	buffer.WriteString(strconv.FormatInt(count, 10))
	buffer.WriteString(`,"rows":[`)
	for i, row := range rows {
		if i > 0 {
			buffer.WriteByte(',')
		}
		buffer.WriteString(`{"origtime":`)
		writeLegacyVoicemailString(&buffer, row.OrigTime)
		buffer.WriteString(`,"duration":`)
		writeLegacyVoicemailString(&buffer, row.Duration)
		buffer.WriteString(`,"id":`)
		buffer.WriteString(strconv.FormatInt(row.ID, 10))
		buffer.WriteString(`,"dir":`)
		writeLegacyVoicemailString(&buffer, row.Dir)
		buffer.WriteString(`,"callerid":`)
		writeLegacyVoicemailString(&buffer, row.CallerID)
		buffer.WriteString(`,"mailboxuser":`)
		writeLegacyVoicemailString(&buffer, row.MailboxUser)
		buffer.WriteString(`,"type":`)
		writeLegacyVoicemailString(&buffer, row.Type)
		buffer.WriteByte('}')
	}
	buffer.WriteString(`]}`)
	return buffer.Bytes()
}

func writeLegacyVoicemailString(buffer *bytes.Buffer, value sql.NullString) {
	if !value.Valid {
		buffer.WriteString("null")
		return
	}
	writeJSString(buffer, decodeUTF8LikeNode([]byte(value.String)))
}

func isNumericVoicemailID(value string) bool {
	if value == "" {
		return false
	}

	for _, char := range value {
		if char < '0' || char > '9' {
			return false
		}
	}

	return true
}
