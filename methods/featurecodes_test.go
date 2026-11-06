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

func TestParseFeatureCodes_ReturnsFeatureCodesInFileOrder(t *testing.T) {
	output, err := parseFeatureCodes([]byte(`{
		"trunks": {"2001": {"name": "trunk"}},
		"queues": {},
		"feature_codes": {"pickup": "*8", "confbridge_conf": "*87", "dnd_toggle": "*76", "audio_test": "*41"},
		"transfer_context": "from-internal-xfer"
	}`))

	require.NoError(t, err)
	assert.Equal(t, `{"pickup":"*8","confbridge_conf":"*87","dnd_toggle":"*76","audio_test":"*41"}`, string(output))
}

func TestParseFeatureCodes_KeepsNonObjectValues(t *testing.T) {
	output, err := parseFeatureCodes([]byte(`{"trunks":[],"queues":null,"feature_codes":false}`))

	require.NoError(t, err)
	assert.Equal(t, `false`, string(output))
}

func TestParseFeatureCodes_MissingFeatureCodesReturnsEmptyObject(t *testing.T) {
	output, err := parseFeatureCodes([]byte(`{"trunks":{},"queues":{}}`))

	require.NoError(t, err)
	assert.Equal(t, `{}`, string(output))
}

func TestParseFeatureCodes_RejectsWrongFormat(t *testing.T) {
	for _, input := range []string{
		`{"queues":{},"feature_codes":{"pickup":"*8"}}`,
		`{"trunks":{},"queues":"x","feature_codes":{"pickup":"*8"}}`,
		`{"trunks":1,"queues":{},"feature_codes":{"pickup":"*8"}}`,
		`[]`,
		`null`,
		`{"trunks":{}`,
	} {
		_, err := parseFeatureCodes([]byte(input))
		assert.Error(t, err, input)
	}
}

func TestLoadFeatureCodes_ReadsFileAndKeepsLastGoodVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ast_objects.json")
	originalPath := configuration.Config.AstObjectsConfigPath
	defer func() {
		configuration.Config.AstObjectsConfigPath = originalPath
		featureCodesFile.clear()
	}()
	configuration.Config.AstObjectsConfigPath = path
	featureCodesFile.clear()

	assert.Equal(t, `{}`, string(loadFeatureCodes()))

	require.NoError(t, os.WriteFile(path, []byte(`{"trunks":{},"queues":{},"feature_codes":{"pickup":"*8"}}`), 0o600))
	assert.Equal(t, `{"pickup":"*8"}`, string(loadFeatureCodes()))

	require.NoError(t, os.WriteFile(path, []byte(`{"trunks":{},"queues":{},"feature_co`), 0o600))
	assert.Equal(t, `{"pickup":"*8"}`, string(loadFeatureCodes()))

	require.NoError(t, os.WriteFile(path, []byte(`{"trunks":{},"queues":{},"feature_codes":{"pickup":"*88","audio_test":"*41"}}`), 0o600))
	assert.Equal(t, `{"pickup":"*88","audio_test":"*41"}`, string(loadFeatureCodes()))

	require.NoError(t, os.Remove(path))
	assert.Equal(t, `{}`, string(loadFeatureCodes()))
}

func TestGetFeatureCodes_WritesJSON(t *testing.T) {
	gin.SetMode(gin.TestMode)
	originalLoad := loadFeatureCodesFunc
	defer func() {
		loadFeatureCodesFunc = originalLoad
	}()
	loadFeatureCodesFunc = func() []byte { return []byte(`{"pickup":"*8"}`) }

	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodGet, "/astproxy/feature_codes", nil)

	GetFeatureCodes(c)

	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, "application/json; charset=utf-8", recorder.Header().Get("Content-Type"))
	assert.Equal(t, `{"pickup":"*8"}`, recorder.Body.String())
}
