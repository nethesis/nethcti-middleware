/*
 * Copyright (C) 2026 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package store

import (
	"context"
	"database/sql"
	"errors"
	"strconv"

	"github.com/nethesis/nethcti-middleware/db"
)

const (
	legacyVoicemailFrom   = " FROM `voicemessages` AS `voicemessages` WHERE mailboxuser = ?"
	legacyVoicemailFolder = ` AND LOWER(SUBSTRING_INDEX(dir, "/", -1)) = ?`
	legacyVoicemailOrder  = " ORDER BY origtime DESC"
)

type VoicemailMessageRow struct {
	OrigTime    sql.NullString
	Duration    sql.NullString
	ID          int64
	Dir         sql.NullString
	CallerID    sql.NullString
	MailboxUser sql.NullString
	Type        sql.NullString
}

func legacyVoicemailWhere(mailbox string, folder *string) (string, []any) {
	query := legacyVoicemailFrom
	args := []any{mailbox}
	if folder != nil {
		query += legacyVoicemailFolder
		args = append(args, *folder)
	}
	return query + legacyVoicemailOrder, args
}

func CountLegacyVoicemailMessages(ctx context.Context, mailbox string, folder *string) (int64, error) {
	database := db.GetCDRDB()
	if database == nil {
		return 0, errors.New("CDR database not available")
	}

	where, args := legacyVoicemailWhere(mailbox, folder)
	var count int64
	err := database.QueryRowContext(ctx, "SELECT count(*) AS `count`"+where, args...).Scan(&count)
	return count, err
}

func ListLegacyVoicemailMessages(ctx context.Context, mailbox string, folder *string, offset, limit uint64) ([]VoicemailMessageRow, error) {
	database := db.GetCDRDB()
	if database == nil {
		return nil, errors.New("CDR database not available")
	}

	where, args := legacyVoicemailWhere(mailbox, folder)
	query := "SELECT `origtime`, `duration`, `id`, `dir`, `callerid`, `mailboxuser`, LOWER(SUBSTRING_INDEX(dir, \"/\", -1)) AS `type`" +
		where + " LIMIT " + strconv.FormatUint(offset, 10) + ", " + strconv.FormatUint(limit, 10)

	rows, err := database.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	messages := make([]VoicemailMessageRow, 0)
	for rows.Next() {
		var message VoicemailMessageRow
		if err := rows.Scan(&message.OrigTime, &message.Duration, &message.ID, &message.Dir, &message.CallerID, &message.MailboxUser, &message.Type); err != nil {
			return nil, err
		}
		messages = append(messages, message)
	}

	return messages, rows.Err()
}
