/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package models

import (
	"time"
)

type Task struct {
	ID        string      `json:"id" structs:"id"`
	Action    string      `json:"action" structs:"action"`
	Data      interface{} `json:"data" structs:"data"`
	Extra     interface{} `json:"extra" structs:"extra"`
	Queue     string      `json:"queue" structs:"queue"`
	User      string      `json:"user" structs:"user"`
	Timestamp time.Time   `json:"timestamp" structs:"timestamp"`
	Parent    string      `json:"parent" structs:"parent"`
}
