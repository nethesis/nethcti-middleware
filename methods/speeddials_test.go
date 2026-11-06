/*
 * Copyright (C) 2026 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package methods

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nethesis/nethcti-middleware/store"
)

type capturedInsert struct {
	columns []string
	values  []any
}

func captureSpeeddialInserts(t *testing.T, fail func(columns []string) bool) *[]capturedInsert {
	t.Helper()
	original := insertSpeeddialFunc
	t.Cleanup(func() { insertSpeeddialFunc = original })

	var inserts []capturedInsert
	insertSpeeddialFunc = func(_ context.Context, columns []string, values []any) error {
		inserts = append(inserts, capturedInsert{columns: columns, values: values})
		if fail != nil && fail(columns) {
			return errors.New("insert failed")
		}
		return nil
	}
	return &inserts
}

func TestImportSpeeddialsCSV_FollowsLegacyParsing(t *testing.T) {
	inserts := captureSpeeddialInserts(t, nil)

	count := importSpeeddialsCSV(context.Background(), "alice", "name,company,type,owner_id,speeddial_num,firstname\r\nMario,ACME,public,mallory,201,Fn\r\nShort\r\n,EmptyName\r\nLast,Dropped")

	assert.Equal(t, 3, count)
	require.Len(t, *inserts, 3)
	assert.Equal(t, []string{"owner_id", "type", "name", "company", "speeddial_num"}, (*inserts)[0].columns)
	assert.Equal(t, []any{"alice", "speeddial", "Mario", "ACME", "201"}, (*inserts)[0].values)
	assert.Equal(t, []any{"alice", "speeddial", "Short"}, (*inserts)[1].values)
	assert.Equal(t, []string{"owner_id", "type", "company"}, (*inserts)[2].columns)
	assert.Equal(t, []any{"alice", "speeddial", "EmptyName"}, (*inserts)[2].values)
}

func TestImportSpeeddialsCSV_EdgeCases(t *testing.T) {
	inserts := captureSpeeddialInserts(t, nil)
	assert.Equal(t, 0, importSpeeddialsCSV(context.Background(), "alice", "name\nLF\nOnly\n"))
	assert.Equal(t, 0, importSpeeddialsCSV(context.Background(), "alice", ""))
	assert.Equal(t, 1, importSpeeddialsCSV(context.Background(), "alice", "\uFEFFname\r\nBom\r\n"))
	assert.Equal(t, 1, importSpeeddialsCSV(context.Background(), "alice", "company\r\nNoName\r\n"))
	assert.Empty(t, *inserts)

	assert.Equal(t, 2, importSpeeddialsCSV(context.Background(), "alice", "name,company,name\r\nFirst,Co\r\nA,B,Second\r\n"))
	require.Len(t, *inserts, 1)
	assert.Equal(t, []any{"alice", "speeddial", "Second", "B"}, (*inserts)[0].values)
}

func TestImportSpeeddialsCSV_CountsFailedRowsAndEncodesCESU8(t *testing.T) {
	inserts := captureSpeeddialInserts(t, func(columns []string) bool { return len(columns) == 3 })

	count := importSpeeddialsCSV(context.Background(), "alice", "name,company\r\nFails,\r\nEmoji 😀,ok\r\n")

	assert.Equal(t, 2, count)
	require.Len(t, *inserts, 2)
	assert.Equal(t, []any{"alice", "speeddial", "Emoji \xed\xa0\xbd\xed\xb8\x80", "ok"}, (*inserts)[1].values)
}

func runSpeeddialRequest(handler gin.HandlerFunc, method, body string) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(method, "/phonebook/speeddials", strings.NewReader(body))
	c.Set("JWT_PAYLOAD", jwtv5.MapClaims{"id": "alice"})
	handler(c)
	return recorder
}

func csvPayload(prefix, content string) string {
	body, _ := json.Marshal(map[string]string{"file64": prefix + base64.StdEncoding.EncodeToString([]byte(content))})
	return string(body)
}

func TestImportSpeeddialsCSVHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)
	originalAccess := userHasPhonebookAccessFunc
	t.Cleanup(func() { userHasPhonebookAccessFunc = originalAccess })
	userHasPhonebookAccessFunc = func(username string) bool { return username == "alice" }
	inserts := captureSpeeddialInserts(t, nil)

	recorder := runSpeeddialRequest(ImportSpeeddialsCSV, http.MethodPost, csvPayload("data:text/csv;base64,", "name,speeddial_num\r\nMario,201\r\nLuigi,202\r\n"))
	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, "application/json; charset=utf-8", recorder.Header().Get("Content-Type"))
	assert.Equal(t, `{"num":2}`, recorder.Body.String())
	assert.Len(t, *inserts, 2)

	for _, body := range []string{`{"file64":null}`, `{"file64":5}`, `{"other":"x"}`, `[]`, `null`, `not json`, ``} {
		recorder = runSpeeddialRequest(ImportSpeeddialsCSV, http.MethodPost, body)
		assert.Equal(t, http.StatusBadRequest, recorder.Code, body)
		assert.Empty(t, recorder.Body.String(), body)
	}

	recorder = runSpeeddialRequest(ImportSpeeddialsCSV, http.MethodPost, `{"file64":"no-comma"}`)
	assert.Equal(t, http.StatusInternalServerError, recorder.Code)
	assert.Empty(t, recorder.Body.String())

	recorder = runSpeeddialRequest(ImportSpeeddialsCSV, http.MethodPost, `{"file64":","}`)
	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, `{"num":0}`, recorder.Body.String())

	userHasPhonebookAccessFunc = func(string) bool { return false }
	recorder = runSpeeddialRequest(ImportSpeeddialsCSV, http.MethodPost, csvPayload("x,", "name\r\nA\r\n"))
	assert.Equal(t, http.StatusForbidden, recorder.Code)
	assert.Empty(t, recorder.Body.String())

	recorder = runSpeeddialRequest(ImportSpeeddialsCSV, http.MethodPost, `{"file64":1}`)
	assert.Equal(t, http.StatusBadRequest, recorder.Code)
}

func TestGetSpeeddials(t *testing.T) {
	gin.SetMode(gin.TestMode)
	original := listSpeeddialsFunc
	t.Cleanup(func() { listSpeeddialsFunc = original })

	values := make([]sql.NullString, len(store.LegacySpeeddialColumns))
	values[0] = sql.NullString{String: "alice", Valid: true}
	values[1] = sql.NullString{String: "speeddial", Valid: true}
	values[9] = sql.NullString{String: "E\xed\xa0\xbd\xed\xb8\x80x", Valid: true}
	values[11] = sql.NullString{String: "", Valid: true}
	listSpeeddialsFunc = func(_ context.Context, username string) ([]store.SpeeddialRow, error) {
		assert.Equal(t, "alice", username)
		return []store.SpeeddialRow{{ID: 7, Values: values}}, nil
	}

	recorder := runSpeeddialRequest(GetSpeeddials, http.MethodGet, "")

	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, `[{"id":7,"owner_id":"alice","type":"speeddial","homeemail":null,"workemail":null,"homephone":null,"workphone":null,"cellphone":null,"fax":null,"title":null,"company":"E😀x","notes":null,"name":"","homestreet":null,"homepob":null,"homecity":null,"homeprovince":null,"homepostalcode":null,"homecountry":null,"workstreet":null,"workpob":null,"workcity":null,"workprovince":null,"workpostalcode":null,"workcountry":null,"url":null,"extension":null,"speeddial_num":null}]`, recorder.Body.String())

	listSpeeddialsFunc = func(context.Context, string) ([]store.SpeeddialRow, error) { return nil, nil }
	recorder = runSpeeddialRequest(GetSpeeddials, http.MethodGet, "")
	assert.Equal(t, `[]`, recorder.Body.String())

	listSpeeddialsFunc = func(context.Context, string) ([]store.SpeeddialRow, error) { return nil, errors.New("boom") }
	recorder = runSpeeddialRequest(GetSpeeddials, http.MethodGet, "")
	assert.Equal(t, http.StatusInternalServerError, recorder.Code)
	assert.Empty(t, recorder.Body.String())
}

func TestDeleteSpeeddials(t *testing.T) {
	gin.SetMode(gin.TestMode)
	original := deleteSpeeddialsFunc
	t.Cleanup(func() { deleteSpeeddialsFunc = original })

	deleteSpeeddialsFunc = func(_ context.Context, username string) (int64, error) {
		assert.Equal(t, "alice", username)
		return 3, nil
	}
	recorder := runSpeeddialRequest(DeleteSpeeddials, http.MethodDelete, "")
	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, `{"num":3}`, recorder.Body.String())

	deleteSpeeddialsFunc = func(context.Context, string) (int64, error) { return 0, errors.New("boom") }
	recorder = runSpeeddialRequest(DeleteSpeeddials, http.MethodDelete, "")
	assert.Equal(t, http.StatusInternalServerError, recorder.Code)
	assert.Empty(t, recorder.Body.String())
}
