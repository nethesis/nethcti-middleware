/*
 * Copyright (C) 2026 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package methods

import (
	"bytes"
	"database/sql"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	jwt "github.com/appleboy/gin-jwt/v3"
	"github.com/gin-gonic/gin"

	"github.com/nethesis/nethcti-middleware/logs"
	"github.com/nethesis/nethcti-middleware/store"
)

var (
	listExtensionPinsFunc       = store.ListExtensionPins
	countPinProtectedRoutesFunc = store.CountPinProtectedRoutes
)

func GetExtensionPins(c *gin.Context) {
	username, _ := jwt.ExtractClaims(c)["id"].(string)

	var extensions []string
	if user := loadLegacyUsersFunc()[username]; user != nil {
		for _, extension := range user.extensions {
			if extension.kind == "" {
				logs.Log("[ERROR][PIN] main extension " + extension.id + " of user " + username + " is not an extension endpoint")
				c.AbortWithStatus(http.StatusInternalServerError)
				return
			}
			if extension.kind != "webrtc" {
				extensions = append(extensions, extension.id)
			}
		}
	}

	if len(extensions) == 0 {
		c.Data(http.StatusOK, "application/json; charset=utf-8", []byte("{}"))
		return
	}

	pins, err := listExtensionPinsFunc(c.Request.Context(), extensions)
	if err != nil {
		logs.Log("[ERROR][PIN] failed to read pins of user " + username + ": " + err.Error())
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	if len(pins) == 0 {
		c.Data(http.StatusOK, "application/json; charset=utf-8", []byte("[]"))
		return
	}

	c.Data(http.StatusOK, "application/json; charset=utf-8", encodeExtensionPins(pins))
}

func GetPinStatus(c *gin.Context) {
	count, err := countPinProtectedRoutesFunc(c.Request.Context())
	if err != nil {
		logs.Log("[ERROR][PIN] failed to read pin protected routes: " + err.Error())
		c.Data(http.StatusOK, "application/json; charset=utf-8", []byte("{}"))
		return
	}

	c.Data(http.StatusOK, "application/json; charset=utf-8", []byte(`{"enabled":`+strconv.FormatBool(count > 0)+`}`))
}

func encodeExtensionPins(pins []store.ExtensionPinRow) []byte {
	keys := make([]string, 0, len(pins))
	values := make(map[string]store.ExtensionPinRow, len(pins))
	for _, pin := range pins {
		key := strconv.FormatInt(pin.Extension, 10)
		if _, exists := values[key]; !exists {
			keys = append(keys, key)
		}
		values[key] = pin
	}

	var buffer bytes.Buffer
	buffer.WriteByte('{')
	for i, key := range jsOrderedKeys(keys) {
		if i > 0 {
			buffer.WriteByte(',')
		}
		pin := values[key]
		writeJSString(&buffer, key)
		buffer.WriteString(`:{"extension":`)
		buffer.WriteString(key)
		buffer.WriteString(`,"pin":`)
		writeMysql2UTF8MB3String(&buffer, pin.Pin)
		buffer.WriteString(`,"enabled":`)
		buffer.WriteString(strconv.FormatBool(pin.Enabled == 1))
		buffer.WriteByte('}')
	}
	buffer.WriteByte('}')
	return buffer.Bytes()
}

func writeMysql2UTF8MB3String(buffer *bytes.Buffer, value sql.NullString) {
	if !value.Valid {
		buffer.WriteString("null")
		return
	}
	writeJSStringUTF16(buffer, decodeCESU8LikeMysql2(replaceSupplementaryRunes(value.String)))
}

func replaceSupplementaryRunes(value string) string {
	var builder strings.Builder
	for i := 0; i < len(value); {
		char, size := utf8.DecodeRuneInString(value[i:])
		if char > 0xffff {
			builder.WriteByte('?')
		} else {
			builder.WriteString(value[i : i+size])
		}
		i += size
	}
	return builder.String()
}
