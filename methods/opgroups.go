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
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/nethesis/nethcti-middleware/configuration"
	"github.com/nethesis/nethcti-middleware/logs"
)

type operatorGroup struct {
	Name  string
	Users []string
}

type operatorGroupsCacheState struct {
	mu      sync.Mutex
	loaded  bool
	path    string
	modTime time.Time
	size    int64
	groups  []operatorGroup
}

type jsonObjectEntry struct {
	key   string
	value json.RawMessage
}

var (
	operatorGroupsCache    operatorGroupsCacheState
	loadOperatorGroupsFunc = loadOperatorGroups
)

func GetOperatorGroups(c *gin.Context) {
	c.Data(http.StatusOK, "application/json; charset=utf-8", encodeOperatorGroups(loadOperatorGroupsFunc()))
}

func loadOperatorGroups() []operatorGroup {
	path := configuration.Config.OperatorConfigPath
	cache := &operatorGroupsCache
	cache.mu.Lock()
	defer cache.mu.Unlock()

	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			cache.loaded = false
			cache.groups = nil
			return []operatorGroup{}
		}
		logs.Log("[WARNING][OPGROUPS] Failed to stat " + path + ": " + err.Error())
		return cache.fallback(path)
	}

	if cache.loaded && cache.path == path && cache.modTime.Equal(info.ModTime()) && cache.size == info.Size() {
		return cache.groups
	}

	data, err := os.ReadFile(path)
	if err != nil {
		logs.Log("[WARNING][OPGROUPS] Failed to read " + path + ": " + err.Error())
		return cache.fallback(path)
	}

	groups, err := parseOperatorGroups(data)
	if err != nil {
		logs.Log("[WARNING][OPGROUPS] Failed to parse " + path + ": " + err.Error())
		return cache.fallback(path)
	}

	cache.loaded = true
	cache.path = path
	cache.modTime = info.ModTime()
	cache.size = info.Size()
	cache.groups = groups

	return groups
}

func (cache *operatorGroupsCacheState) fallback(path string) []operatorGroup {
	if cache.loaded && cache.path == path {
		return cache.groups
	}
	return []operatorGroup{}
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

func jsPropertyOrder(count int, keyAt func(int) string) []int {
	indexKeys := make([]int, 0)
	otherKeys := make([]int, 0, count)
	for i := 0; i < count; i++ {
		if _, ok := jsArrayIndex(keyAt(i)); ok {
			indexKeys = append(indexKeys, i)
		} else {
			otherKeys = append(otherKeys, i)
		}
	}

	sort.SliceStable(indexKeys, func(a, b int) bool {
		left, _ := jsArrayIndex(keyAt(indexKeys[a]))
		right, _ := jsArrayIndex(keyAt(indexKeys[b]))
		return left < right
	})

	return append(indexKeys, otherKeys...)
}

func jsArrayIndex(key string) (uint64, bool) {
	if key == "" || (len(key) > 1 && key[0] == '0') {
		return 0, false
	}
	for _, char := range key {
		if char < '0' || char > '9' {
			return 0, false
		}
	}
	value, err := strconv.ParseUint(key, 10, 64)
	if err != nil || value >= 4294967295 {
		return 0, false
	}
	return value, true
}

func encodeOperatorGroups(groups []operatorGroup) []byte {
	var buffer bytes.Buffer
	buffer.WriteByte('{')
	for i, group := range groups {
		if i > 0 {
			buffer.WriteByte(',')
		}
		buffer.Write(marshalJSONNoEscape(group.Name))
		buffer.WriteString(`:{"users":`)
		users := group.Users
		if users == nil {
			users = []string{}
		}
		buffer.Write(marshalJSONNoEscape(users))
		buffer.WriteByte('}')
	}
	buffer.WriteByte('}')
	return buffer.Bytes()
}

func marshalJSONNoEscape(value any) []byte {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return []byte("null")
	}
	return bytes.TrimRight(buffer.Bytes(), "\n")
}
