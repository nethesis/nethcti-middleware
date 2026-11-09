/*
 * Copyright (C) 2026 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/nethesis/nethcti-middleware/db"
)

type ExtensionPinRow struct {
	Extension int64
	Pin       sql.NullString
	Enabled   int64
}

func ListExtensionPins(ctx context.Context, extensions []string) ([]ExtensionPinRow, error) {
	database := db.GetDB()
	if database == nil {
		return nil, errors.New("database not available")
	}

	args := make([]any, len(extensions))
	for i, extension := range extensions {
		args[i] = extension
	}
	query := "SELECT `extension`, `pin`, `enabled` FROM `asterisk`.`pin` WHERE `extension` IN (" +
		strings.TrimSuffix(strings.Repeat("?, ", len(extensions)), ", ") + ")"

	rows, err := database.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	pins := make([]ExtensionPinRow, 0)
	for rows.Next() {
		var pin ExtensionPinRow
		if err := rows.Scan(&pin.Extension, &pin.Pin, &pin.Enabled); err != nil {
			return nil, err
		}
		pins = append(pins, pin)
	}

	return pins, rows.Err()
}

func CountPinProtectedRoutes(ctx context.Context) (int64, error) {
	database := db.GetDB()
	if database == nil {
		return 0, errors.New("database not available")
	}

	var count int64
	err := database.QueryRowContext(ctx, "SELECT COUNT(*) AS `count` FROM `asterisk`.`pin_protected_routes` WHERE enabled=1").Scan(&count)
	return count, err
}
