/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package models

type UserAuthorizations struct {
	Username string   `json:"username" structs:"username"`
	Role     string   `json:"role" structs:"role"`
	Actions  []string `json:"actions" structs:"actions"`
	OtpPass  bool     `json:"otppass" structs:"otppass"`
}
