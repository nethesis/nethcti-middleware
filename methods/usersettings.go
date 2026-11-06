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

	jwt "github.com/appleboy/gin-jwt/v3"
	"github.com/gin-gonic/gin"

	"github.com/nethesis/nethcti-middleware/logs"
	"github.com/nethesis/nethcti-middleware/store"
)

var (
	listUserSettingsFunc   = store.ListUserSettings
	getProfileParamURLFunc = store.GetProfileParamURL
	userProfileIDFunc      = userProfileID
)

func GetAllAvatars(c *gin.Context) {
	settings, err := listUserSettingsFunc(c.Request.Context())
	if err != nil {
		logs.Log("[ERROR][AVATARS] failed to read user settings: " + err.Error())
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	c.Data(http.StatusOK, "application/json; charset=utf-8", encodeAllAvatars(settings))
}

func GetParamURL(c *gin.Context) {
	username, _ := jwt.ExtractClaims(c)["id"].(string)
	profileID, ok := userProfileIDFunc(username)
	if !ok {
		c.Data(http.StatusOK, "application/json; charset=utf-8", []byte("{}"))
		return
	}

	paramURL, err := getProfileParamURLFunc(c.Request.Context(), profileID)
	if err != nil {
		logs.Log("[ERROR][PARAMURL] failed to read parameterized URL for profile " + profileID + ": " + err.Error())
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	c.Data(http.StatusOK, "application/json; charset=utf-8", encodeProfileParamURL(paramURL))
}

func userProfileID(username string) (string, bool) {
	profile, err := store.GetUserProfile(username)
	if err != nil {
		return "", false
	}
	return profile.ID, true
}

func encodeAllAvatars(settings []store.UserSettingRow) []byte {
	type userAvatar struct {
		value sql.NullString
		set   bool
	}

	var usernames []string
	avatars := map[string]*userAvatar{}
	for _, setting := range settings {
		avatar, seen := avatars[setting.Username]
		if !seen {
			avatar = &userAvatar{}
			avatars[setting.Username] = avatar
			usernames = append(usernames, setting.Username)
		}
		if setting.KeyName == "avatar" {
			avatar.value = setting.Value
			avatar.set = true
		}
	}

	var buffer bytes.Buffer
	buffer.WriteByte('{')
	first := true
	for _, index := range jsPropertyOrder(len(usernames), func(i int) string { return usernames[i] }) {
		username := usernames[index]
		avatar := avatars[username]
		if !avatar.set {
			continue
		}
		if !first {
			buffer.WriteByte(',')
		}
		first = false
		writeJSString(&buffer, username)
		buffer.WriteByte(':')
		if avatar.value.Valid {
			writeJSString(&buffer, avatar.value.String)
		} else {
			buffer.WriteString("null")
		}
	}
	buffer.WriteByte('}')
	return buffer.Bytes()
}

func encodeProfileParamURL(paramURL *store.ProfileParamURL) []byte {
	if paramURL == nil {
		return []byte("{}")
	}

	var buffer bytes.Buffer
	buffer.WriteString(`{"id":`)
	buffer.WriteString(strconv.FormatUint(paramURL.ID, 10))
	buffer.WriteString(`,"profile_id":`)
	buffer.WriteString(strconv.FormatUint(paramURL.ProfileID, 10))
	buffer.WriteString(`,"url":`)
	writeJSString(&buffer, paramURL.URL)
	buffer.WriteString(`,"only_queues":`)
	switch paramURL.OnlyQueues {
	case 0:
		buffer.WriteString("false")
	case 1:
		buffer.WriteString("true")
	default:
		buffer.WriteString(strconv.FormatInt(paramURL.OnlyQueues, 10))
	}
	buffer.WriteByte('}')
	return buffer.Bytes()
}
