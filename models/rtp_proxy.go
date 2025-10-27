/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package models

type PublishProxy struct {
	Name string `json:"intercom_name"`
}

type SubscribeProxy struct {
	PubAddr string `json:"publisher"`
}
