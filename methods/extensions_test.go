/*
 * Copyright (C) 2026 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package methods

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/nethesis/nethcti-middleware/logs"
	"github.com/nethesis/nethcti-middleware/store"
)

func TestGetExtensionByMainExtensionAndType(t *testing.T) {
	logs.Init("nethcti-test")
	gin.SetMode(gin.TestMode)

	profilesJSON := `{
		"3": {"id":"3","name":"Advanced","macro_permissions": {"phonebook": {"value": true, "permissions": [{"id":"12","name":"ad_phonebook","value":true}]}}}
	}`
	usersJSON := `{
		"cristian": {
			"name": "Cristian Manoni",
			"endpoints": {
				"mainextension": {
					"203": {}
				},
				"extension": {
					"203": {
						"type": "mobile",
						"user": "203",
						"password": "be676f8179d71fa41da13e7154361bc6"
					},
					"91203": {
						"type": "nethlink",
						"user": "91203",
						"password": "93113a56c79a399aa8ae67460650fe74"
					}
				},
				"voicemail": {
					"203": {}
				},
				"email": {},
				"cellphone": {}
			},
			"profile_id": "3"
		}
	}`

	profilesFile := writeTempFile(t, "profiles.json", profilesJSON)
	usersFile := writeTempFile(t, "users.json", usersJSON)

	if err := store.InitProfiles(profilesFile, usersFile); err != nil {
		t.Fatalf("InitProfiles failed: %v", err)
	}

	router := gin.New()
	router.GET("/extensions/:mainextension/:type", GetExtensionByMainExtensionAndType)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/extensions/203/nethlink", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to decode response body: %v", err)
	}

	if body["username"] != "cristian" {
		t.Fatalf("unexpected username: got %q want %q", body["username"], "cristian")
	}
	if body["extension"] != "91203" {
		t.Fatalf("unexpected extension: got %q want %q", body["extension"], "91203")
	}
	if body["mainextension"] != "203" {
		t.Fatalf("unexpected mainextension: got %q want %q", body["mainextension"], "203")
	}
	if body["type"] != "nethlink" {
		t.Fatalf("unexpected type: got %q want %q", body["type"], "nethlink")
	}
}
