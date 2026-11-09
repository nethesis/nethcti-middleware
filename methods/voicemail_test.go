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
	"github.com/stretchr/testify/require"

	"github.com/nethesis/nethcti-middleware/store"
)

type voicemailQuery struct {
	mailbox string
	folder  *string
	offset  uint64
	limit   uint64
}

type voicemailMocks struct {
	counts  []voicemailQuery
	lists   []voicemailQuery
	proxied []string
}

func nullString(value string) sql.NullString {
	return sql.NullString{String: value, Valid: true}
}

func setupVoicemailMocks(t *testing.T, users legacyUsers, count int64, rows []store.VoicemailMessageRow) *voicemailMocks {
	t.Helper()
	gin.SetMode(gin.TestMode)

	originalUsers := loadLegacyUsersFunc
	originalCount := countVoicemailMessagesFunc
	originalList := listVoicemailMessagesFunc
	originalProxy := proxyV1RequestFunc
	t.Cleanup(func() {
		loadLegacyUsersFunc = originalUsers
		countVoicemailMessagesFunc = originalCount
		listVoicemailMessagesFunc = originalList
		proxyV1RequestFunc = originalProxy
	})

	mocks := &voicemailMocks{}
	loadLegacyUsersFunc = func() legacyUsers { return users }
	countVoicemailMessagesFunc = func(_ context.Context, mailbox string, folder *string) (int64, error) {
		mocks.counts = append(mocks.counts, voicemailQuery{mailbox: mailbox, folder: folder})
		return count, nil
	}
	listVoicemailMessagesFunc = func(_ context.Context, mailbox string, folder *string, offset, limit uint64) ([]store.VoicemailMessageRow, error) {
		mocks.lists = append(mocks.lists, voicemailQuery{mailbox: mailbox, folder: folder, offset: offset, limit: limit})
		return rows, nil
	}
	proxyV1RequestFunc = func(c *gin.Context, path string, allowAnonymous bool) {
		assert.False(t, allowAnonymous)
		mocks.proxied = append(mocks.proxied, path)
		c.Status(http.StatusTeapot)
	}
	return mocks
}

func voicemailUsers(voicemails map[string][]string) legacyUsers {
	users := legacyUsers{}
	for name, ids := range voicemails {
		users[name] = &legacyUser{voicemails: ids}
	}
	return users
}

func runVoicemailRequest(user, target string) *httptest.ResponseRecorder {
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("JWT_PAYLOAD", jwtv5.MapClaims{"id": user})
		c.Next()
	})
	router.GET("/voicemail/list/:id", ListVoicemailByID)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, target, nil))
	return recorder
}

var sampleVoicemailRows = []store.VoicemailMessageRow{
	{OrigTime: nullString("1700000100"), Duration: nullString("5"), ID: 2, Dir: nullString("/var/spool/asterisk/voicemail/default/201/Old"), CallerID: nullString("\"Luigi\" <334> & \xed\xa0\xbd"), MailboxUser: nullString("201"), Type: nullString("old")},
	{OrigTime: nullString(""), ID: 4, CallerID: nullString("x\u2028"), MailboxUser: nullString("201")},
}

func TestListVoicemailByID_ReturnsSingleRow(t *testing.T) {
	mocks := setupVoicemailMocks(t, voicemailUsers(map[string][]string{"alice": {"201"}}), 2, sampleVoicemailRows)

	recorder := runVoicemailRequest("alice", "/voicemail/list/2")

	require.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, `{"count":1,"rows":[{"callerid":"\"Luigi\" \u003c334\u003e \u0026 `+"\uFFFD\uFFFD\uFFFD"+`","dir":"/var/spool/asterisk/voicemail/default/201/Old","duration":"5","id":2,"mailboxuser":"201","origtime":"1700000100","type":"old"}]}`, recorder.Body.String())
	assert.Equal(t, []voicemailQuery{{mailbox: "201", offset: 0, limit: legacyVoicemailAllRows}}, mocks.lists)
	assert.Empty(t, mocks.proxied)

	recorder = runVoicemailRequest("alice", "/voicemail/list/02")
	assert.Equal(t, `{"count":0,"rows":[]}`, recorder.Body.String())
}

func TestListVoicemailByID_NumericFailures(t *testing.T) {
	setupVoicemailMocks(t, voicemailUsers(map[string][]string{"alice": {"201", "202"}, "bob": nil}), 0, nil)

	for _, user := range []string{"alice", "bob", "carl"} {
		recorder := runVoicemailRequest(user, "/voicemail/list/4")
		assert.Equal(t, http.StatusBadGateway, recorder.Code, user)
		assert.Equal(t, `{"code":502,"data":null,"message":"failed to fetch voicemail list"}`, recorder.Body.String(), user)
	}

	recorder := runVoicemailRequest("alice", "/voicemail/list/%20")
	assert.Equal(t, http.StatusBadRequest, recorder.Code)
}

func TestListVoicemailMessages_EncodesLikeLegacyServer(t *testing.T) {
	mocks := setupVoicemailMocks(t, voicemailUsers(map[string][]string{"alice": {"201"}}), 7, sampleVoicemailRows)

	recorder := runVoicemailRequest("alice", "/voicemail/list/all")

	require.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, `{"count":7,"rows":[{"origtime":"1700000100","duration":"5","id":2,"dir":"/var/spool/asterisk/voicemail/default/201/Old","callerid":"\"Luigi\" <334> & `+"\uFFFD\uFFFD\uFFFD"+`","mailboxuser":"201","type":"old"},{"origtime":"","duration":null,"id":4,"dir":null,"callerid":"x`+"\u2028"+`","mailboxuser":"201","type":null}]}`, recorder.Body.String())
	require.Len(t, mocks.counts, 1)
	assert.Nil(t, mocks.counts[0].folder)
	assert.Equal(t, []voicemailQuery{{mailbox: "201", offset: 0, limit: legacyVoicemailAllRows}}, mocks.lists)
}

func TestListVoicemailMessages_UserStates(t *testing.T) {
	mocks := setupVoicemailMocks(t, voicemailUsers(map[string][]string{"alice": {"201", "202"}, "bob": nil}), 3, sampleVoicemailRows)

	for _, user := range []string{"alice", "bob"} {
		recorder := runVoicemailRequest(user, "/voicemail/list/inbox")
		assert.Equal(t, http.StatusOK, recorder.Code, user)
		assert.Equal(t, `[]`, recorder.Body.String(), user)
	}

	for _, user := range []string{"carl", "Bob", "constructor"} {
		recorder := runVoicemailRequest(user, "/voicemail/list/inbox")
		assert.Equal(t, http.StatusInternalServerError, recorder.Code, user)
		assert.Empty(t, recorder.Body.String(), user)
	}

	assert.Empty(t, mocks.counts)
}

func TestListVoicemailMessages_FolderFilter(t *testing.T) {
	mocks := setupVoicemailMocks(t, voicemailUsers(map[string][]string{"alice": {"201"}}), 0, nil)

	cases := map[string]string{
		"/voicemail/list/INBOX":              "INBOX",
		"/voicemail/list/inbox%20":           "inbox ",
		"/voicemail/list/%20inbox":           " inbox",
		"/voicemail/list/in%22%22box":        `in"box`,
		"/voicemail/list/inbo%5Cx":           "inbox",
		"/voicemail/list/a%5Cnb%5C0":         "a\nb\x00",
		"/voicemail/list/in%5C%25box%5C_":    `in\%box\_`,
		"/voicemail/list/%C3%AFnbox":         "ïnbox",
		"/voicemail/list/%5C%C3%A8%5C%5C%3F": `è\?`,
		"/voicemail/list/a%5C%22":            `a"`,
	}
	for target, expected := range cases {
		mocks.counts = nil
		recorder := runVoicemailRequest("alice", target)
		assert.Equal(t, `{"count":0,"rows":[]}`, recorder.Body.String(), target)
		require.Len(t, mocks.counts, 1, target)
		require.NotNil(t, mocks.counts[0].folder, target)
		assert.Equal(t, expected, *mocks.counts[0].folder, target)
	}
	assert.Empty(t, mocks.lists)

	mocks.counts = nil
	for _, target := range []string{"/voicemail/list/a%22b", "/voicemail/list/%22", "/voicemail/list/inbox%5C", "/voicemail/list/a%5C%5C%22"} {
		recorder := runVoicemailRequest("alice", target)
		assert.Equal(t, http.StatusInternalServerError, recorder.Code, target)
		assert.Empty(t, recorder.Body.String(), target)
	}
	assert.Empty(t, mocks.counts)

	recorder := runVoicemailRequest("alice", "/voicemail/list/%FF")
	assert.Equal(t, http.StatusBadRequest, recorder.Code)
	assert.Equal(t, `{"code":"BadRequestError","message":"URI malformed"}`, recorder.Body.String())
}

func TestListVoicemailMessages_Pagination(t *testing.T) {
	mocks := setupVoicemailMocks(t, voicemailUsers(map[string][]string{"alice": {"201"}}), 5, []store.VoicemailMessageRow{})

	cases := map[string][2]uint64{
		"":                            {0, legacyVoicemailAllRows},
		"?":                           {0, legacyVoicemailAllRows},
		"?offset=2":                   {2, legacyVoicemailAllRows},
		"?limit=3":                    {0, 3},
		"?offset=1&limit=0":           {1, 0},
		"?offset=&limit=":             {0, legacyVoicemailAllRows},
		"?limit=2&limit=1":            {0, 2},
		"?offset=0x1f":                {31, legacyVoicemailAllRows},
		"?offset=1e3&limit=12abc":     {1, 12},
		"?limit=%2B4&offset=+3":       {3, 4},
		"?offset=%E2%80%A8%C2%A07":    {7, legacyVoicemailAllRows},
		"?off%73et=6&lim%69t=1":       {6, 1},
		"?offset=-0":                  {0, legacyVoicemailAllRows},
		"?limit=18446744073709549568": {0, 18446744073709550000},
		"?a[b]=1&a.b=2&limit=9":       {0, 9},
		"?offset":                     {0, legacyVoicemailAllRows},
		"?limit=1.5e400":              {0, 1},
	}
	for query, expected := range cases {
		mocks.lists = nil
		recorder := runVoicemailRequest("alice", "/voicemail/list/all"+query)
		assert.Equal(t, http.StatusOK, recorder.Code, query)
		assert.Equal(t, `{"count":5,"rows":[]}`, recorder.Body.String(), query)
		assert.Equal(t, []voicemailQuery{{mailbox: "201", offset: expected[0], limit: expected[1]}}, mocks.lists, query)
	}

	mocks.lists = nil
	for _, query := range []string{"?offset=abc", "?limit=-1", "?offset=%zz", "?limit=99999999999999999999", "?limit=,1"} {
		recorder := runVoicemailRequest("alice", "/voicemail/list/all"+query)
		assert.Equal(t, http.StatusInternalServerError, recorder.Code, query)
		assert.Empty(t, recorder.Body.String(), query)
	}
	assert.Empty(t, mocks.lists)
}

func TestListVoicemailMessages_EmptyFolderSkipsPagination(t *testing.T) {
	mocks := setupVoicemailMocks(t, voicemailUsers(map[string][]string{"alice": {"201"}}), 0, nil)

	recorder := runVoicemailRequest("alice", "/voicemail/list/zzz?offset=abc")

	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, `{"count":0,"rows":[]}`, recorder.Body.String())
	assert.Empty(t, mocks.lists)
}

func TestListVoicemailMessages_ComplexQueryGoesToLegacyServer(t *testing.T) {
	mocks := setupVoicemailMocks(t, voicemailUsers(map[string][]string{"alice": {"201"}}), 1, nil)

	for _, query := range []string{"offset[x]=1", "offset%5B%5D=1", "limit.x=1", "%5Blimit%5D=2", "offset=1&limit[0]=3", ".x=1"} {
		recorder := runVoicemailRequest("alice", "/voicemail/list/all?"+query)
		assert.Equal(t, http.StatusTeapot, recorder.Code, query)
	}
	assert.Len(t, mocks.proxied, 6)
	assert.Equal(t, "/voicemail/list/all", mocks.proxied[0])
	assert.Empty(t, mocks.counts)
}

func TestListVoicemailMessages_DatabaseErrors(t *testing.T) {
	setupVoicemailMocks(t, voicemailUsers(map[string][]string{"alice": {"201"}}), 1, nil)
	countVoicemailMessagesFunc = func(context.Context, string, *string) (int64, error) { return 0, errors.New("boom") }

	recorder := runVoicemailRequest("alice", "/voicemail/list/all")
	assert.Equal(t, http.StatusInternalServerError, recorder.Code)
	assert.Empty(t, recorder.Body.String())

	countVoicemailMessagesFunc = func(context.Context, string, *string) (int64, error) { return 1, nil }
	listVoicemailMessagesFunc = func(context.Context, string, *string, uint64, uint64) ([]store.VoicemailMessageRow, error) {
		return nil, errors.New("boom")
	}
	recorder = runVoicemailRequest("alice", "/voicemail/list/all")
	assert.Equal(t, http.StatusInternalServerError, recorder.Code)

	recorder = runVoicemailRequest("alice", "/voicemail/list/3")
	assert.Equal(t, http.StatusBadGateway, recorder.Code)
}
