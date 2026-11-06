/*
 * Copyright (C) 2026 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package methods

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/nethesis/nethcti-middleware/logs"
	"github.com/nethesis/nethcti-middleware/store"
)

var legacyCTIPhonebookInsertColumns = []string{
	"owner_id", "type", "name", "homeemail", "workemail", "homephone", "workphone", "cellphone",
	"fax", "title", "company", "notes", "homestreet", "homepob", "homecity", "homeprovince",
	"homepostalcode", "homecountry", "workstreet", "workpob", "workcity", "workprovince",
	"workpostalcode", "workcountry", "url", "extension", "speeddial_num",
}

var (
	listSpeeddialsFunc         = store.ListLegacySpeeddials
	deleteSpeeddialsFunc       = store.DeleteLegacySpeeddials
	insertSpeeddialFunc        = store.InsertCTIPhonebookColumns
	userHasPhonebookAccessFunc = userHasPhonebookAccess
)

func GetSpeeddials(c *gin.Context) {
	username, err := getUsernameFromContext(c)
	if err != nil {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	speeddials, err := listSpeeddialsFunc(c.Request.Context(), encodeCESU8(username))
	if err != nil {
		logs.Log("[ERROR][SPEEDDIALS] failed to list speed dials of user " + username + ": " + err.Error())
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	c.Data(http.StatusOK, "application/json; charset=utf-8", encodeLegacySpeeddials(speeddials))
}

func DeleteSpeeddials(c *gin.Context) {
	username, err := getUsernameFromContext(c)
	if err != nil {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	deleted, err := deleteSpeeddialsFunc(c.Request.Context(), encodeCESU8(username))
	if err != nil {
		logs.Log("[ERROR][SPEEDDIALS] failed to delete speed dials of user " + username + ": " + err.Error())
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	c.Data(http.StatusOK, "application/json; charset=utf-8", []byte(`{"num":`+strconv.FormatInt(deleted, 10)+`}`))
}

func ImportSpeeddialsCSV(c *gin.Context) {
	username, err := getUsernameFromContext(c)
	if err != nil {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	var payload map[string]json.RawMessage
	if err := json.NewDecoder(c.Request.Body).Decode(&payload); err != nil {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	var file64 string
	raw := bytes.TrimSpace(payload["file64"])
	if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &file64) != nil {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	if !userHasPhonebookAccessFunc(username) {
		c.AbortWithStatus(http.StatusForbidden)
		return
	}

	parts := strings.Split(file64, ",")
	if len(parts) < 2 {
		logs.Log("[ERROR][SPEEDDIALS] invalid csv import payload from user " + username)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	imported := importSpeeddialsCSV(c.Request.Context(), username, decodeUTF8LikeNode(decodeBase64LikeNode(parts[1])))
	c.Data(http.StatusOK, "application/json; charset=utf-8", []byte(`{"num":`+strconv.Itoa(imported)+`}`))
}

func importSpeeddialsCSV(ctx context.Context, username, content string) int {
	lines := strings.Split(content, "\r\n")
	headers := strings.Split(lines[0], ",")
	rows := lines[1:]
	if len(rows) > 0 {
		rows = rows[:len(rows)-1]
	}

	for _, line := range rows {
		fields := strings.Split(line, ",")
		data := make(map[string]*string, len(headers))
		for i, header := range headers {
			if i < len(fields) {
				data[header] = &fields[i]
			} else {
				data[header] = nil
			}
		}
		if data["name"] == nil {
			continue
		}

		columns := make([]string, 0, len(legacyCTIPhonebookInsertColumns))
		values := make([]any, 0, len(legacyCTIPhonebookInsertColumns))
		for _, column := range legacyCTIPhonebookInsertColumns {
			var value string
			switch column {
			case "owner_id":
				value = username
			case "type":
				value = "speeddial"
			default:
				if data[column] == nil {
					continue
				}
				value = *data[column]
			}
			if value == "" {
				continue
			}
			columns = append(columns, column)
			values = append(values, encodeCESU8(value))
		}

		if err := insertSpeeddialFunc(ctx, columns, values); err != nil {
			logs.Log("[WARNING][SPEEDDIALS] skipped csv speed dial row of user " + username + ": " + err.Error())
		}
	}

	return len(rows)
}

func userHasPhonebookAccess(username string) bool {
	capabilities, err := store.GetUserCapabilities(username)
	if err != nil {
		return false
	}
	return capabilities["phonebook"]
}

func encodeLegacySpeeddials(speeddials []store.SpeeddialRow) []byte {
	var buffer bytes.Buffer
	buffer.WriteByte('[')
	for i, speeddial := range speeddials {
		if i > 0 {
			buffer.WriteByte(',')
		}
		buffer.WriteString(`{"id":`)
		buffer.WriteString(strconv.FormatInt(speeddial.ID, 10))
		for j, column := range store.LegacySpeeddialColumns {
			buffer.WriteString(`,"`)
			buffer.WriteString(column)
			buffer.WriteString(`":`)
			if speeddial.Values[j].Valid {
				writeJSStringUTF16(&buffer, decodeCESU8LikeMysql2(speeddial.Values[j].String))
			} else {
				buffer.WriteString("null")
			}
		}
		buffer.WriteByte('}')
	}
	buffer.WriteByte(']')
	return buffer.Bytes()
}
