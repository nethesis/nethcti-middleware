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

func TestLegacySpeeddials(t *testing.T) {
	ctx := context.Background()
	database := db.GetDB()
	_, err := database.Exec("DELETE FROM cti_phonebook WHERE owner_id IN ('sd-alice', 'sd-bob')")
	require.NoError(t, err)
	defer database.Exec("DELETE FROM cti_phonebook WHERE owner_id IN ('sd-alice', 'sd-bob')")

	require.NoError(t, InsertCTIPhonebookColumns(ctx, []string{"owner_id", "type", "name", "speeddial_num"}, []any{"sd-alice", "speeddial", "Zeta", "2"}))
	require.NoError(t, InsertCTIPhonebookColumns(ctx, []string{"owner_id", "type", "company"}, []any{"sd-alice", "speeddial", "NoName"}))
	require.NoError(t, InsertCTIPhonebookColumns(ctx, []string{"owner_id", "type", "name"}, []any{"sd-alice", "speeddial", "Alpha"}))
	require.NoError(t, InsertCTIPhonebookColumns(ctx, []string{"owner_id", "type", "name"}, []any{"sd-alice", "private", "Private"}))
	require.NoError(t, InsertCTIPhonebookColumns(ctx, []string{"owner_id", "type", "name"}, []any{"sd-bob", "speeddial", "Bob"}))
	assert.Error(t, InsertCTIPhonebookColumns(ctx, []string{"owner_id", "type", "name", "homephone"}, []any{"sd-alice", "speeddial", "Long", "12345678901234567890123456"}))

	speeddials, err := ListLegacySpeeddials(ctx, "sd-alice")
	require.NoError(t, err)
	require.Len(t, speeddials, 3)
	names := make([]any, 0, len(speeddials))
	for _, speeddial := range speeddials {
		require.Len(t, speeddial.Values, len(LegacySpeeddialColumns))
		assert.Equal(t, "sd-alice", speeddial.Values[0].String)
		assert.Equal(t, "speeddial", speeddial.Values[1].String)
		if speeddial.Values[11].Valid {
			names = append(names, speeddial.Values[11].String)
		} else {
			names = append(names, nil)
		}
	}
	assert.Equal(t, []any{nil, "Alpha", "Zeta"}, names)
	assert.Equal(t, "2", speeddials[2].Values[26].String)
	assert.False(t, speeddials[2].Values[2].Valid)

	deleted, err := DeleteLegacySpeeddials(ctx, "sd-alice")
	require.NoError(t, err)
	assert.Equal(t, int64(3), deleted)

	deleted, err = DeleteLegacySpeeddials(ctx, "sd-alice")
	require.NoError(t, err)
	assert.Equal(t, int64(0), deleted)

	remaining, err := ListLegacySpeeddials(ctx, "sd-bob")
	require.NoError(t, err)
	assert.Len(t, remaining, 1)

	var privateCount int
	require.NoError(t, database.QueryRow("SELECT COUNT(*) FROM cti_phonebook WHERE owner_id = 'sd-alice' AND type = 'private'").Scan(&privateCount))
	assert.Equal(t, 1, privateCount)
}
