/*
 * Copyright (C) 2026 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package methods

import (
	"errors"
	"os"
	"sync"
	"time"

	"github.com/nethesis/nethcti-middleware/logs"
)

type cachedConfigFile[T any] struct {
	mu      sync.Mutex
	name    string
	parse   func([]byte) (T, error)
	empty   func() T
	loaded  bool
	path    string
	modTime time.Time
	size    int64
	value   T
}

func newCachedConfigFile[T any](name string, parse func([]byte) (T, error), empty func() T) *cachedConfigFile[T] {
	return &cachedConfigFile[T]{name: name, parse: parse, empty: empty}
}

func (file *cachedConfigFile[T]) load(path string) T {
	file.mu.Lock()
	defer file.mu.Unlock()

	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			file.reset()
			return file.empty()
		}
		logs.Log("[WARNING][" + file.name + "] Failed to stat " + path + ": " + err.Error())
		return file.fallback(path)
	}

	if file.loaded && file.path == path && file.modTime.Equal(info.ModTime()) && file.size == info.Size() {
		return file.value
	}

	data, err := os.ReadFile(path)
	if err != nil {
		logs.Log("[WARNING][" + file.name + "] Failed to read " + path + ": " + err.Error())
		return file.fallback(path)
	}

	value, err := file.parse(data)
	if err != nil {
		logs.Log("[WARNING][" + file.name + "] Failed to parse " + path + ": " + err.Error())
		return file.fallback(path)
	}

	file.loaded = true
	file.path = path
	file.modTime = info.ModTime()
	file.size = info.Size()
	file.value = value

	return value
}

func (file *cachedConfigFile[T]) fallback(path string) T {
	if file.loaded && file.path == path {
		return file.value
	}
	return file.empty()
}

func (file *cachedConfigFile[T]) reset() {
	var zero T
	file.loaded = false
	file.path = ""
	file.value = zero
}

func (file *cachedConfigFile[T]) clear() {
	file.mu.Lock()
	defer file.mu.Unlock()
	file.reset()
}
