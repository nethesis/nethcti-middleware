/*
 * Copyright (C) 2026 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package methods

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/nethesis/nethcti-middleware/configuration"
)

type legacyUser struct {
	voicemails []string
	extensions []legacyUserExtension
}

type legacyUserExtension struct {
	id   string
	kind string
}

type legacyUsers map[string]*legacyUser

var (
	legacyUsersFile = newCachedConfigFile("USERS", parseLegacyUsers, func() legacyUsers { return legacyUsers{} })

	loadLegacyUsersFunc = loadLegacyUsers

	legacyExtensionTypes = map[string]bool{"physical": true, "webrtc": true, "mobile": true, "nethlink": true}

	jsObjectPrototypeProperties = map[string]bool{
		"constructor": true, "__proto__": true, "__defineGetter__": true, "__defineSetter__": true,
		"__lookupGetter__": true, "__lookupSetter__": true, "hasOwnProperty": true, "isPrototypeOf": true,
		"propertyIsEnumerable": true, "toLocaleString": true, "toString": true, "valueOf": true,
	}
)

func loadLegacyUsers() legacyUsers {
	return legacyUsersFile.load(configuration.Config.UsersConfigPath)
}

func parseLegacyUsers(data []byte) (legacyUsers, error) {
	var root json.RawMessage
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, err
	}

	entries, err := decodeJSONContainerEntries(root)
	if err != nil {
		return nil, err
	}

	keys := make([]string, 0, len(entries))
	values := make(map[string]json.RawMessage, len(entries))
	for _, entry := range entries {
		keys = append(keys, entry.key)
		values[entry.key] = entry.value
	}

	for _, key := range jsOrderedKeys(keys) {
		value := values[key]
		keys = removeKey(keys, key)
		delete(values, key)
		lower := strings.ToLower(key)
		if lower == "__proto__" {
			continue
		}
		if _, exists := values[lower]; !exists {
			keys = append(keys, lower)
		}
		values[lower] = value
	}

	ordered := jsOrderedKeys(keys)
	created := 0
	for created < len(ordered) && legacyUserHasName(values[ordered[created]]) {
		created++
	}

	users := make(legacyUsers, created)
	for _, key := range ordered[:created] {
		if created < len(ordered) {
			users[key] = &legacyUser{}
			continue
		}
		users[key] = &legacyUser{
			voicemails: legacyUserVoicemails(values[key]),
			extensions: legacyUserExtensions(values[key]),
		}
	}

	return users, nil
}

func jsOrderedKeys(keys []string) []string {
	order := jsPropertyOrder(len(keys), func(i int) string { return keys[i] })
	ordered := make([]string, len(order))
	for i, index := range order {
		ordered[i] = keys[index]
	}
	return ordered
}

func removeKey(keys []string, key string) []string {
	for i, current := range keys {
		if current == key {
			return append(keys[:i], keys[i+1:]...)
		}
	}
	return keys
}

func jsonObjectField(raw json.RawMessage, name string) (json.RawMessage, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, false
	}
	entries, err := decodeJSONContainerEntries(trimmed)
	if err != nil {
		return nil, false
	}
	for _, entry := range entries {
		if entry.key == name {
			return entry.value, true
		}
	}
	return nil, false
}

func jsonValueKind(raw json.RawMessage) byte {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return 0
	}
	return trimmed[0]
}

func isJSTypeofObjectValue(raw json.RawMessage) bool {
	kind := jsonValueKind(raw)
	return kind == '{' || kind == '[' || kind == 'n'
}

func legacyUserHasName(raw json.RawMessage) bool {
	name, ok := jsonObjectField(raw, "name")
	return ok && jsonValueKind(name) == '"'
}

func legacyUserEndpoints(raw json.RawMessage, endpointType string) []jsonObjectEntry {
	endpoints, ok := jsonObjectField(raw, "endpoints")
	if !ok {
		return nil
	}
	value, ok := jsonObjectField(endpoints, endpointType)
	if !ok {
		return nil
	}
	kind := jsonValueKind(value)
	if kind != '{' && kind != '[' {
		return nil
	}
	entries, err := decodeJSONContainerEntries(bytes.TrimSpace(value))
	if err != nil {
		return nil
	}
	return entries
}

func legacyUserVoicemails(raw json.RawMessage) []string {
	var voicemails []string
	for _, entry := range legacyUserEndpoints(raw, "voicemail") {
		if !isJSTypeofObjectValue(entry.value) {
			break
		}
		voicemails = append(voicemails, entry.key)
	}
	return voicemails
}

func legacyUserExtensions(raw json.RawMessage) []legacyUserExtension {
	keys := []string{}
	kinds := map[string]string{}

	for _, entry := range legacyUserEndpoints(raw, "mainextension") {
		if !isJSTypeofObjectValue(entry.value) {
			break
		}
		keys = append(keys, entry.key)
		kinds[entry.key] = ""
	}

	for _, entry := range legacyUserEndpoints(raw, "extension") {
		typeValue, ok := jsonObjectField(entry.value, "type")
		if !ok || jsonValueKind(typeValue) != '"' {
			break
		}
		var extensionType string
		if err := json.Unmarshal(typeValue, &extensionType); err != nil || jsObjectPrototypeProperties[extensionType] {
			break
		}
		if !legacyExtensionTypes[extensionType] {
			continue
		}
		if _, exists := kinds[entry.key]; !exists {
			keys = append(keys, entry.key)
		}
		kinds[entry.key] = extensionType
	}

	extensions := make([]legacyUserExtension, 0, len(keys))
	for _, key := range jsOrderedKeys(keys) {
		extensions = append(extensions, legacyUserExtension{id: key, kind: kinds[key]})
	}
	return extensions
}
