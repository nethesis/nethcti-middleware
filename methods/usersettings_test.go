/*
 * Copyright (C) 2026 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package methods

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"

	"github.com/nethesis/nethcti-middleware/store"
)

func avatarSetting(username, key string, value *string) store.UserSettingRow {
	row := store.UserSettingRow{Username: username, KeyName: key}
	if value != nil {
		row.Value = sql.NullString{String: *value, Valid: true}
	}
	return row
}

func stringPtr(value string) *string {
	return &value
}

func TestEncodeAllAvatars_FollowsLegacyOrderAndValues(t *testing.T) {
	output := encodeAllAvatars([]store.UserSettingRow{
		avatarSetting("zeta", "default_extension", stringPtr("201")),
		avatarSetting("alice", "avatar", stringPtr("data:image/png;base64,AAA=")),
		avatarSetting("300", "avatar", stringPtr("n300")),
		avatarSetting("Alice", "theme", stringPtr("dark")),
		avatarSetting("20", "avatar", stringPtr("n20")),
		avatarSetting("carol", "avatar", nil),
		avatarSetting("zeta", "avatar", stringPtr("z")),
		avatarSetting("01", "avatar", stringPtr("lz")),
		avatarSetting("dave", "Avatar", stringPtr("ignored")),
		avatarSetting("erin", "avatar", stringPtr(`q"\`+"\n<&> ")),
	})

	assert.Equal(t, `{"20":"n20","300":"n300","zeta":"z","alice":"data:image/png;base64,AAA=","carol":null,"01":"lz","erin":"q\"\\\n<&>`+" "+`"}`, string(output))
}

func TestEncodeAllAvatars_Empty(t *testing.T) {
	assert.Equal(t, `{}`, string(encodeAllAvatars(nil)))
	assert.Equal(t, `{}`, string(encodeAllAvatars([]store.UserSettingRow{avatarSetting("a", "theme", stringPtr("x"))})))
}

func TestEncodeProfileParamURL(t *testing.T) {
	assert.Equal(t, `{}`, string(encodeProfileParamURL(nil)))

	cases := map[int64]string{0: "false", 1: "true", 2: "2", -1: "-1"}
	for onlyQueues, expected := range cases {
		output := encodeProfileParamURL(&store.ProfileParamURL{ID: 4294967295, ProfileID: 3, URL: `https://crm.it/?n=$CALLER_NUMBER&x="<y>"`, OnlyQueues: onlyQueues})
		assert.Equal(t, `{"id":4294967295,"profile_id":3,"url":"https://crm.it/?n=$CALLER_NUMBER&x=\"<y>\"","only_queues":`+expected+`}`, string(output))
	}
}

func TestGetAllAvatars(t *testing.T) {
	gin.SetMode(gin.TestMode)
	originalList := listUserSettingsFunc
	defer func() {
		listUserSettingsFunc = originalList
	}()

	t.Run("ok", func(t *testing.T) {
		listUserSettingsFunc = func(context.Context) ([]store.UserSettingRow, error) {
			return []store.UserSettingRow{avatarSetting("alice", "avatar", stringPtr("a"))}, nil
		}
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequest(http.MethodGet, "/user/all_avatars", nil)

		GetAllAvatars(c)

		assert.Equal(t, http.StatusOK, recorder.Code)
		assert.Equal(t, "application/json; charset=utf-8", recorder.Header().Get("Content-Type"))
		assert.Equal(t, `{"alice":"a"}`, recorder.Body.String())
	})

	t.Run("db error", func(t *testing.T) {
		listUserSettingsFunc = func(context.Context) ([]store.UserSettingRow, error) {
			return nil, errors.New("boom")
		}
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequest(http.MethodGet, "/user/all_avatars", nil)

		GetAllAvatars(c)

		assert.Equal(t, http.StatusInternalServerError, recorder.Code)
		assert.Empty(t, recorder.Body.String())
	})
}

func TestGetParamURL(t *testing.T) {
	gin.SetMode(gin.TestMode)
	originalGet := getProfileParamURLFunc
	originalProfile := userProfileIDFunc
	defer func() {
		getProfileParamURLFunc = originalGet
		userProfileIDFunc = originalProfile
	}()

	run := func() *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequest(http.MethodGet, "/user/paramurl", nil)
		c.Set("JWT_PAYLOAD", jwtv5.MapClaims{"id": "alice"})
		GetParamURL(c)
		return recorder
	}

	t.Run("profile url", func(t *testing.T) {
		var requestedProfile string
		userProfileIDFunc = func(username string) (string, bool) {
			assert.Equal(t, "alice", username)
			return "3", true
		}
		getProfileParamURLFunc = func(_ context.Context, profileID string) (*store.ProfileParamURL, error) {
			requestedProfile = profileID
			return &store.ProfileParamURL{ID: 84, ProfileID: 3, URL: "https://crm.it", OnlyQueues: 1}, nil
		}

		recorder := run()

		assert.Equal(t, "3", requestedProfile)
		assert.Equal(t, http.StatusOK, recorder.Code)
		assert.Equal(t, "application/json; charset=utf-8", recorder.Header().Get("Content-Type"))
		assert.Equal(t, `{"id":84,"profile_id":3,"url":"https://crm.it","only_queues":true}`, recorder.Body.String())
	})

	t.Run("no url for profile", func(t *testing.T) {
		userProfileIDFunc = func(string) (string, bool) { return "3", true }
		getProfileParamURLFunc = func(context.Context, string) (*store.ProfileParamURL, error) { return nil, nil }

		recorder := run()

		assert.Equal(t, http.StatusOK, recorder.Code)
		assert.Equal(t, `{}`, recorder.Body.String())
	})

	t.Run("user without profile", func(t *testing.T) {
		userProfileIDFunc = func(string) (string, bool) { return "", false }
		getProfileParamURLFunc = func(context.Context, string) (*store.ProfileParamURL, error) {
			t.Fatal("database must not be queried")
			return nil, nil
		}

		recorder := run()

		assert.Equal(t, http.StatusOK, recorder.Code)
		assert.Equal(t, `{}`, recorder.Body.String())
	})

	t.Run("db error", func(t *testing.T) {
		userProfileIDFunc = func(string) (string, bool) { return "3", true }
		getProfileParamURLFunc = func(context.Context, string) (*store.ProfileParamURL, error) { return nil, errors.New("boom") }

		recorder := run()

		assert.Equal(t, http.StatusInternalServerError, recorder.Code)
		assert.Empty(t, recorder.Body.String())
	})
}
