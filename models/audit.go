/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package models

import (
	"time"
)

type Audit struct {
	ID        int       `json:"id" structs:"id"`
	User      string    `json:"user" structs:"user"`
	Action    string    `json:"action" structs:"action"`
	Data      string    `json:"data" structs:"data"`
	Timestamp time.Time `json:"timestamp" structs:"timestamp"`
}
