/*
 * Copyright (C) 2026 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package methods

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/nethesis/nethcti-middleware/configuration"
)

type operatorGroup struct {
	Name  string
	Users []string
}

type jsonObjectEntry struct {
	key   string
	value json.RawMessage
}

var (
	operatorGroupsFile = newCachedConfigFile("OPGROUPS", parseOperatorGroups, func() []operatorGroup { return []operatorGroup{} })

	loadOperatorGroupsFunc = loadOperatorGroups
)

func GetOperatorGroups(c *gin.Context) {
	c.Data(http.StatusOK, "application/json; charset=utf-8", encodeOperatorGroups(loadOperatorGroupsFunc()))
}

func loadOperatorGroups() []operatorGroup {
	return operatorGroupsFile.load(configuration.Config.OperatorConfigPath)
}

func parseOperatorGroups(data []byte) ([]operatorGroup, error) {
	var root json.RawMessage
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, err
	}

	var top map[string]json.RawMessage
	if err := json.Unmarshal(root, &top); err != nil {
		return []operatorGroup{}, nil
	}

	entries, err := decodeJSONContainerEntries(top["groups"])
	if err != nil {
		return nil, err
	}

	groups := make([]operatorGroup, 0, len(entries))
	for _, entry := range entries {
		value, ok := jsValueToString(entry.value)
		if !ok {
			break
		}
		groups = append(groups, operatorGroup{
			Name:  entry.key,
			Users: uniqueJSKeys(strings.Split(strings.ToLower(value), ",")),
		})
	}

	return groups, nil
}

func decodeJSONContainerEntries(raw json.RawMessage) ([]jsonObjectEntry, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, nil
	}

	var entries []jsonObjectEntry
	switch trimmed[0] {
	case '{':
		decoder := json.NewDecoder(bytes.NewReader(trimmed))
		if _, err := decoder.Token(); err != nil {
			return nil, err
		}
		positions := map[string]int{}
		for decoder.More() {
			token, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			key, _ := token.(string)
			var value json.RawMessage
			if err := decoder.Decode(&value); err != nil {
				return nil, err
			}
			if index, exists := positions[key]; exists {
				entries[index].value = value
				continue
			}
			positions[key] = len(entries)
			entries = append(entries, jsonObjectEntry{key: key, value: value})
		}
	case '[':
		var items []json.RawMessage
		if err := json.Unmarshal(trimmed, &items); err != nil {
			return nil, err
		}
		for index, item := range items {
			entries = append(entries, jsonObjectEntry{key: strconv.Itoa(index), value: item})
		}
		return entries, nil
	default:
		return nil, nil
	}

	order := jsPropertyOrder(len(entries), func(i int) string { return entries[i].key })
	ordered := make([]jsonObjectEntry, len(entries))
	for i, index := range order {
		ordered[i] = entries[index]
	}

	return ordered, nil
}

func jsValueToString(raw json.RawMessage) (string, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return "", false
	}

	switch trimmed[0] {
	case 'n':
		return "", false
	case '"':
		var value string
		if err := json.Unmarshal(trimmed, &value); err != nil {
			return "", false
		}
		return value, true
	case '[':
		var items []json.RawMessage
		if err := json.Unmarshal(trimmed, &items); err != nil {
			return "", false
		}
		parts := make([]string, len(items))
		for i, item := range items {
			if value, ok := jsValueToString(item); ok {
				parts[i] = value
			}
		}
		return strings.Join(parts, ","), true
	case '{':
		return "[object Object]", true
	case 't', 'f':
		return string(trimmed), true
	default:
		number, err := strconv.ParseFloat(string(trimmed), 64)
		if err != nil {
			return string(trimmed), true
		}
		return strconv.FormatFloat(number, 'f', -1, 64), true
	}
}

func uniqueJSKeys(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	unique := make([]string, 0, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		unique = append(unique, value)
	}

	order := jsPropertyOrder(len(unique), func(i int) string { return unique[i] })
	ordered := make([]string, len(unique))
	for i, index := range order {
		ordered[i] = unique[index]
	}

	return ordered
}

func encodeOperatorGroups(groups []operatorGroup) []byte {
	var buffer bytes.Buffer
	buffer.WriteByte('{')
	for i, group := range groups {
		if i > 0 {
			buffer.WriteByte(',')
		}
		writeJSString(&buffer, group.Name)
		buffer.WriteString(`:{"users":[`)
		for j, user := range group.Users {
			if j > 0 {
				buffer.WriteByte(',')
			}
			writeJSString(&buffer, user)
		}
		buffer.WriteString(`]}`)
	}
	buffer.WriteByte('}')
	return buffer.Bytes()
}
