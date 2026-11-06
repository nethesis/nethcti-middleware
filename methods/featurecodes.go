/*
 * Copyright (C) 2026 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package methods

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/nethesis/nethcti-middleware/configuration"
)

var (
	featureCodesFile = newCachedConfigFile("FEATURE-CODES", parseFeatureCodes, func() []byte { return []byte("{}") })

	loadFeatureCodesFunc = loadFeatureCodes
)

func GetFeatureCodes(c *gin.Context) {
	c.Data(http.StatusOK, "application/json; charset=utf-8", loadFeatureCodesFunc())
}

func loadFeatureCodes() []byte {
	return featureCodesFile.load(configuration.Config.AstObjectsConfigPath)
}

func parseFeatureCodes(data []byte) ([]byte, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return nil, err
	}
	if !isJSTypeofObject(top["trunks"]) || !isJSTypeofObject(top["queues"]) {
		return nil, errors.New("wrong file format: trunks and queues must be objects")
	}

	featureCodes, ok := top["feature_codes"]
	if !ok {
		return []byte("{}"), nil
	}

	return normalizeJSONLikeJavaScript(featureCodes)
}

func isJSTypeofObject(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return false
	}
	return trimmed[0] == '{' || trimmed[0] == '[' || bytes.Equal(trimmed, []byte("null"))
}
