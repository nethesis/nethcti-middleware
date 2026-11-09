/*
 * Copyright (C) 2026 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package store

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nethesis/nethcti-middleware/db"
)

func TestLegacyVoicemailMessages(t *testing.T) {
	ctx := context.Background()
	_, err := db.GetDB().Exec("CREATE DATABASE IF NOT EXISTS asteriskcdrdb")
	require.NoError(t, err)
	cdr := db.GetCDRDB()
	require.NotNil(t, cdr)
	_, err = cdr.Exec("CREATE TABLE IF NOT EXISTS `voicemessages` (" +
		"`id` int(11) NOT NULL AUTO_INCREMENT, `msgnum` int(11) NOT NULL DEFAULT '0', `dir` varchar(80) DEFAULT '', " +
		"`context` varchar(80) DEFAULT '', `macrocontext` varchar(80) DEFAULT '', `callerid` varchar(255) DEFAULT '', " +
		"`origtime` varchar(40) DEFAULT '', `duration` varchar(20) DEFAULT '', `mailboxuser` varchar(80) DEFAULT '', " +
		"`mailboxcontext` varchar(80) DEFAULT '', `recording` longblob, `flag` varchar(128) DEFAULT '', `read` tinyint(1) DEFAULT '0', " +
		"`msg_id` varchar(40) DEFAULT '', PRIMARY KEY (`id`), KEY `dir` (`dir`)) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_general_ci")
	require.NoError(t, err)

	_, err = cdr.Exec("DELETE FROM voicemessages WHERE mailboxuser IN ('vm-test-1', 'vm-test-2')")
	require.NoError(t, err)
	defer cdr.Exec("DELETE FROM voicemessages WHERE mailboxuser IN ('vm-test-1', 'vm-test-2')")

	_, err = cdr.Exec("INSERT INTO voicemessages (dir, callerid, origtime, duration, mailboxuser) VALUES " +
		"('/var/spool/asterisk/voicemail/default/1/INBOX', '\"Mario\" <201>', '1700000300', '14', 'vm-test-1'), " +
		"('/var/spool/asterisk/voicemail/default/1/Old', 'Luigi', '1700000100', '5', 'vm-test-1'), " +
		"('/var/spool/asterisk/voicemail/default/1/INBOX', NULL, '1700000200', NULL, 'vm-test-1'), " +
		"(NULL, 'x', '1700000400', '1', 'vm-test-1'), " +
		"('/var/spool/asterisk/voicemail/default/2/INBOX', 'Other', '1700000500', '3', 'vm-test-2')")
	require.NoError(t, err)

	count, err := CountLegacyVoicemailMessages(ctx, "vm-test-1", nil)
	require.NoError(t, err)
	assert.Equal(t, int64(4), count)

	rows, err := ListLegacyVoicemailMessages(ctx, "vm-test-1", nil, 0, 10000000000000)
	require.NoError(t, err)
	require.Len(t, rows, 4)
	origTimes := make([]string, 0, len(rows))
	for _, row := range rows {
		origTimes = append(origTimes, row.OrigTime.String)
	}
	assert.Equal(t, []string{"1700000400", "1700000300", "1700000200", "1700000100"}, origTimes)
	assert.False(t, rows[0].Dir.Valid)
	assert.False(t, rows[0].Type.Valid)
	assert.Equal(t, "inbox", rows[1].Type.String)
	assert.Equal(t, `"Mario" <201>`, rows[1].CallerID.String)
	assert.False(t, rows[2].CallerID.Valid)
	assert.False(t, rows[2].Duration.Valid)

	for _, folder := range []string{"inbox", "INBOX", "inbox ", "ïnbox"} {
		count, err = CountLegacyVoicemailMessages(ctx, "vm-test-1", &folder)
		require.NoError(t, err)
		assert.Equal(t, int64(2), count, folder)
	}

	folder := "old"
	rows, err = ListLegacyVoicemailMessages(ctx, "vm-test-1", &folder, 0, 10000000000000)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, "Luigi", rows[0].CallerID.String)

	rows, err = ListLegacyVoicemailMessages(ctx, "vm-test-1", nil, 1, 2)
	require.NoError(t, err)
	require.Len(t, rows, 2)
	assert.Equal(t, "1700000300", rows[0].OrigTime.String)

	rows, err = ListLegacyVoicemailMessages(ctx, "vm-test-1", nil, 18446744073709550000, 0)
	require.NoError(t, err)
	assert.Empty(t, rows)
}
