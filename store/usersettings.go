/*
 * Copyright (C) 2026 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package store

import (
	"context"
	"database/sql"
	"errors"

	"github.com/nethesis/nethcti-middleware/db"
)

type UserSettingRow struct {
	Username string
	KeyName  string
	Value    sql.NullString
}

type ProfileParamURL struct {
	ID         uint64
	ProfileID  uint64
	URL        string
	OnlyQueues int64
}

const profileParamURLTable = "asterisk.rest_cti_profiles_paramurl"

func ListUserSettings(ctx context.Context) ([]UserSettingRow, error) {
	database := db.GetDB()
	if database == nil {
		return nil, errors.New("database not initialized")
	}

	rows, err := database.QueryContext(ctx, "SELECT `username`, `key_name`, `value` FROM `user_settings`")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var settings []UserSettingRow
	for rows.Next() {
		var row UserSettingRow
		if err := rows.Scan(&row.Username, &row.KeyName, &row.Value); err != nil {
			return nil, err
		}
		settings = append(settings, row)
	}

	return settings, rows.Err()
}

func GetProfileParamURL(ctx context.Context, profileID string) (*ProfileParamURL, error) {
	database := db.GetDB()
	if database == nil {
		return nil, errors.New("database not initialized")
	}

	var paramURL ProfileParamURL
	err := database.QueryRowContext(ctx,
		"SELECT `id`, `profile_id`, `url`, `only_queues` FROM "+profileParamURLTable+" WHERE `profile_id` = ? LIMIT 1",
		profileID,
	).Scan(&paramURL.ID, &paramURL.ProfileID, &paramURL.URL, &paramURL.OnlyQueues)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &paramURL, nil
}
