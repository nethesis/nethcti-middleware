/*
 * Copyright (C) 2026 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package methods

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nethesis/nethcti-middleware/configuration"
)

func TestParseOperatorGroups_PreservesFileOrderLowercasesAndDeduplicates(t *testing.T) {
	groups, err := parseOperatorGroups([]byte(`{"groups":{"Zeta":["Bob","alice"],"Alpha":["carol","BOB","carol"]}}`))

	require.NoError(t, err)
	assert.Equal(t, []operatorGroup{
		{Name: "Zeta", Users: []string{"bob", "alice"}},
		{Name: "Alpha", Users: []string{"carol", "bob"}},
	}, groups)
}

func TestParseOperatorGroups_OrdersIntegerKeysFirstLikeJavaScript(t *testing.T) {
	groups, err := parseOperatorGroups([]byte(`{"groups":{"b":["x"],"10":["y"],"2":["z"],"01":["w"]}}`))

	require.NoError(t, err)
	names := make([]string, 0, len(groups))
	for _, group := range groups {
		names = append(names, group.Name)
	}
	assert.Equal(t, []string{"2", "10", "b", "01"}, names)

	users, err := parseOperatorGroups([]byte(`{"groups":{"g":["zed","300","20","amy"]}}`))
	require.NoError(t, err)
	assert.Equal(t, []string{"20", "300", "zed", "amy"}, users[0].Users)
}

func TestParseOperatorGroups_EmptyShapes(t *testing.T) {
	for _, input := range []string{
		`{"groups":[]}`,
		`{"groups":{}}`,
		`{}`,
		`[]`,
		`null`,
		`{"groups":null}`,
		`{"groups":"abc"}`,
	} {
		groups, err := parseOperatorGroups([]byte(input))
		require.NoError(t, err, input)
		assert.Empty(t, groups, input)
	}
}

func TestParseOperatorGroups_ListEncodedGroupsUseIndexes(t *testing.T) {
	groups, err := parseOperatorGroups([]byte(`{"groups":[["a"],["b","c"]]}`))

	require.NoError(t, err)
	assert.Equal(t, []operatorGroup{
		{Name: "0", Users: []string{"a"}},
		{Name: "1", Users: []string{"b", "c"}},
	}, groups)
}

func TestParseOperatorGroups_ValueConversionsMatchLegacyServer(t *testing.T) {
	groups, err := parseOperatorGroups([]byte(`{"groups":{"str":"X,y","empty":[],"nested":["a",null,["B","c"]],"num":[1,2.5],"last":null,"skipped":["z"]}}`))

	require.NoError(t, err)
	assert.Equal(t, []operatorGroup{
		{Name: "str", Users: []string{"x", "y"}},
		{Name: "empty", Users: []string{""}},
		{Name: "nested", Users: []string{"a", "", "b", "c"}},
		{Name: "num", Users: []string{"1", "2.5"}},
	}, groups)
}

func TestParseOperatorGroups_InvalidJSON(t *testing.T) {
	_, err := parseOperatorGroups([]byte(`{"groups":{"a":["x"]`))

	assert.Error(t, err)
}

func TestLoadOperatorGroups_ReadsFileAndKeepsLastGoodVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "operator.json")
	originalPath := configuration.Config.OperatorConfigPath
	defer func() {
		configuration.Config.OperatorConfigPath = originalPath
		operatorGroupsFile.clear()
	}()
	configuration.Config.OperatorConfigPath = path
	operatorGroupsFile.clear()

	assert.Empty(t, loadOperatorGroups())

	require.NoError(t, os.WriteFile(path, []byte(`{"groups":{"Sales":["alice"]}}`), 0o600))
	assert.Equal(t, []operatorGroup{{Name: "Sales", Users: []string{"alice"}}}, loadOperatorGroups())

	require.NoError(t, os.WriteFile(path, []byte(`{"groups":{"Sales":["ali`), 0o600))
	assert.Equal(t, []operatorGroup{{Name: "Sales", Users: []string{"alice"}}}, loadOperatorGroups())

	require.NoError(t, os.WriteFile(path, []byte(`{"groups":{"Support":["bob","carol"]}}`), 0o600))
	assert.Equal(t, []operatorGroup{{Name: "Support", Users: []string{"bob", "carol"}}}, loadOperatorGroups())

	require.NoError(t, os.Remove(path))
	assert.Empty(t, loadOperatorGroups())
}

func TestLoadOperatorGroups_InvalidFileWithoutCacheReturnsEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "operator.json")
	originalPath := configuration.Config.OperatorConfigPath
	defer func() {
		configuration.Config.OperatorConfigPath = originalPath
		operatorGroupsFile.clear()
	}()
	configuration.Config.OperatorConfigPath = path
	operatorGroupsFile.clear()

	require.NoError(t, os.WriteFile(path, []byte(`not json`), 0o600))

	assert.Empty(t, loadOperatorGroups())
}

func TestGetOperatorGroups_WritesLegacyShapeInFileOrder(t *testing.T) {
	gin.SetMode(gin.TestMode)
	originalLoad := loadOperatorGroupsFunc
	defer func() {
		loadOperatorGroupsFunc = originalLoad
	}()
	loadOperatorGroupsFunc = func() []operatorGroup {
		return []operatorGroup{
			{Name: "Zeta", Users: []string{"bob", "alice"}},
			{Name: "R&D <lab>", Users: []string{"carol"}},
			{Name: "Nil", Users: nil},
		}
	}

	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodGet, "/astproxy/opgroups", nil)

	GetOperatorGroups(c)

	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, "application/json; charset=utf-8", recorder.Header().Get("Content-Type"))
	assert.Equal(t, `{"Zeta":{"users":["bob","alice"]},"R&D <lab>":{"users":["carol"]},"Nil":{"users":[]}}`, recorder.Body.String())
}

func TestGetOperatorGroups_EmptyReturnsEmptyObject(t *testing.T) {
	gin.SetMode(gin.TestMode)
	originalLoad := loadOperatorGroupsFunc
	defer func() {
		loadOperatorGroupsFunc = originalLoad
	}()
	loadOperatorGroupsFunc = func() []operatorGroup { return []operatorGroup{} }

	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodGet, "/astproxy/opgroups", nil)

	GetOperatorGroups(c)

	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, `{}`, recorder.Body.String())
}

func TestLoadPhonebookOperatorGroups_UsesLocalOperatorGroups(t *testing.T) {
	originalLoad := loadOperatorGroupsFunc
	defer func() {
		loadOperatorGroupsFunc = originalLoad
	}()
	loadOperatorGroupsFunc = func() []operatorGroup {
		return []operatorGroup{
			{Name: "Sales", Users: []string{"alice"}},
			{Name: "Support", Users: []string{"bob", "alice"}},
		}
	}

	groups, err := loadPhonebookOperatorGroups("alice")

	require.NoError(t, err)
	assert.Equal(t, map[string]legacyPhonebookOperatorGroup{
		"Sales":   {Users: []string{"alice"}},
		"Support": {Users: []string{"bob", "alice"}},
	}, groups)
	assert.Equal(t, []string{"Sales", "Support"}, computeVisibleGroupNames("alice", groups))
}
