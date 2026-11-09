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

func ensureAsteriskPinTables(t *testing.T) {
	t.Helper()
	database := db.GetDB()
	for _, statement := range []string{
		"CREATE DATABASE IF NOT EXISTS asterisk",
		"CREATE TABLE IF NOT EXISTS asterisk.pin (`extension` int(11) NOT NULL, `pin` varchar(10) COLLATE utf8mb4_unicode_ci DEFAULT NULL, " +
			"`enabled` tinyint(1) NOT NULL DEFAULT '1', PRIMARY KEY (`extension`)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
		"CREATE TABLE IF NOT EXISTS asterisk.pin_protected_routes (`route_id` int(11) NOT NULL DEFAULT '0', `enabled` tinyint(1) NOT NULL DEFAULT '0', " +
			"KEY `route_id` (`route_id`)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
	} {
		_, err := database.Exec(statement)
		require.NoError(t, err)
	}
}

func TestListExtensionPins(t *testing.T) {
	ensureAsteriskPinTables(t)
	database := db.GetDB()
	_, err := database.Exec("DELETE FROM asterisk.pin WHERE extension IN (98201, 98202, 98203)")
	require.NoError(t, err)
	defer database.Exec("DELETE FROM asterisk.pin WHERE extension IN (98201, 98202, 98203)")
	_, err = database.Exec("INSERT INTO asterisk.pin (extension, pin, enabled) VALUES (98201, '1234', 1), (98202, NULL, 0), (98203, '9', 1)")
	require.NoError(t, err)

	pins, err := ListExtensionPins(context.Background(), []string{"98202", "98201abc", " 98203", "99999"})
	require.NoError(t, err)
	require.Len(t, pins, 3)
	assert.Equal(t, int64(98201), pins[0].Extension)
	assert.Equal(t, "1234", pins[0].Pin.String)
	assert.Equal(t, int64(1), pins[0].Enabled)
	assert.False(t, pins[1].Pin.Valid)
	assert.Equal(t, int64(0), pins[1].Enabled)
	assert.Equal(t, int64(98203), pins[2].Extension)

	pins, err = ListExtensionPins(context.Background(), []string{"99999"})
	require.NoError(t, err)
	assert.Empty(t, pins)
}

func TestCountPinProtectedRoutes(t *testing.T) {
	ensureAsteriskPinTables(t)
	database := db.GetDB()
	_, err := database.Exec("DELETE FROM asterisk.pin_protected_routes")
	require.NoError(t, err)
	defer database.Exec("DELETE FROM asterisk.pin_protected_routes")

	count, err := CountPinProtectedRoutes(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int64(0), count)

	_, err = database.Exec("INSERT INTO asterisk.pin_protected_routes (route_id, enabled) VALUES (1, 1), (2, 0), (3, 1), (4, 2)")
	require.NoError(t, err)

	count, err = CountPinProtectedRoutes(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int64(2), count)
}
