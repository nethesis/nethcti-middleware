/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package methods

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePhonebookCSV_GroupTypeAccepted(t *testing.T) {
	csvContent := strings.NewReader("name,type,workphone\nAlice,\"group: Sales,Support,Sales \",+39123\n")

	entries, response, err := parsePhonebookCSV(csvContent)

	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "group:Sales,Support", entries[0].Type)
	assert.Equal(t, 1, response.TotalRows)
	assert.Equal(t, 0, response.SkippedRows)
	assert.Empty(t, response.ErrorMessages)
}

func TestParsePhonebookCSV_InvalidGroupTypeRejected(t *testing.T) {
	csvContent := strings.NewReader("name,type\nAlice,group:public\n")

	entries, response, err := parsePhonebookCSV(csvContent)

	require.NoError(t, err)
	assert.Empty(t, entries)
	assert.Equal(t, 1, response.TotalRows)
	assert.Equal(t, 1, response.SkippedRows)
	require.Len(t, response.ErrorMessages, 1)
	assert.Contains(t, response.ErrorMessages[0], "invalid type")
}

func TestParsePhonebookCSV_TraditionalTypesStillAccepted(t *testing.T) {
	csvContent := strings.NewReader("name,type\nAlice,Public\nBob,private\n")

	entries, response, err := parsePhonebookCSV(csvContent)

	require.NoError(t, err)
	require.Len(t, entries, 2)
	assert.Equal(t, "public", entries[0].Type)
	assert.Equal(t, "private", entries[1].Type)
	assert.Equal(t, 2, response.TotalRows)
	assert.Equal(t, 0, response.SkippedRows)
}

func TestParsePhonebookCSV_NewFieldsImported(t *testing.T) {
	csvContent := strings.NewReader(
		"name,firstname,lastname,job,facebook,instagram,linkedin,workphone2,cellphone2,otherphone,otheremail\n" +
			"Alice Rossi,Alice,Rossi,Engineer,fb.me/alice,@alice,in/alice,+390111,+390222,+390333,alice.other@example.com\n",
	)

	entries, response, err := parsePhonebookCSV(csvContent)

	require.NoError(t, err)
	require.Len(t, entries, 1)
	entry := entries[0]
	assert.Equal(t, "Alice", entry.FirstName)
	assert.Equal(t, "Rossi", entry.LastName)
	assert.Equal(t, "Engineer", entry.Job)
	assert.Equal(t, "fb.me/alice", entry.Facebook)
	assert.Equal(t, "@alice", entry.Instagram)
	assert.Equal(t, "in/alice", entry.LinkedIn)
	assert.Equal(t, "+390111", entry.WorkPhone2)
	assert.Equal(t, "+390222", entry.CellPhone2)
	assert.Equal(t, "+390333", entry.OtherPhone)
	assert.Equal(t, "alice.other@example.com", entry.OtherEmail)
	assert.Equal(t, 0, response.SkippedRows)
	assert.Empty(t, response.ErrorMessages)
}