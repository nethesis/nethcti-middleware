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

var LegacySpeeddialColumns = []string{
	"owner_id", "type", "homeemail", "workemail", "homephone", "workphone", "cellphone", "fax",
	"title", "company", "notes", "name", "homestreet", "homepob", "homecity", "homeprovince",
	"homepostalcode", "homecountry", "workstreet", "workpob", "workcity", "workprovince",
	"workpostalcode", "workcountry", "url", "extension", "speeddial_num",
}

type SpeeddialRow struct {
	ID     int64
	Values []sql.NullString
}

func ListLegacySpeeddials(ctx context.Context, username string) ([]SpeeddialRow, error) {
	database := db.GetDB()
	if database == nil {
		return nil, errors.New("database not initialized")
	}

	query := "SELECT `id`, `" + strings.Join(LegacySpeeddialColumns, "`, `") + "` FROM `cti_phonebook` WHERE owner_id=? AND type=\"speeddial\" ORDER BY name ASC, company ASC"
	rows, err := database.QueryContext(ctx, query, username)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var speeddials []SpeeddialRow
	for rows.Next() {
		row := SpeeddialRow{Values: make([]sql.NullString, len(LegacySpeeddialColumns))}
		dest := make([]any, 0, len(LegacySpeeddialColumns)+1)
		dest = append(dest, &row.ID)
		for i := range row.Values {
			dest = append(dest, &row.Values[i])
		}
		if err := rows.Scan(dest...); err != nil {
			return nil, err
		}
		speeddials = append(speeddials, row)
	}

	return speeddials, rows.Err()
}

func DeleteLegacySpeeddials(ctx context.Context, username string) (int64, error) {
	database := db.GetDB()
	if database == nil {
		return 0, errors.New("database not initialized")
	}

	result, err := database.ExecContext(ctx, "DELETE FROM `cti_phonebook` WHERE owner_id=? AND type=\"speeddial\"", username)
	if err != nil {
		return 0, err
	}

	return result.RowsAffected()
}

func InsertCTIPhonebookColumns(ctx context.Context, columns []string, values []any) error {
	database := db.GetDB()
	if database == nil {
		return errors.New("database not initialized")
	}

	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(columns)), ",")
	query := "INSERT INTO `cti_phonebook` (`" + strings.Join(columns, "`,`") + "`) VALUES (" + placeholders + ")"
	_, err := database.ExecContext(ctx, query, values...)
	return err
}
