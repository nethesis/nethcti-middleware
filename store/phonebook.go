/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package store

import (
	"context"
	"errors"

	"github.com/nethesis/nethcti-middleware/db"
	"github.com/nethesis/nethcti-middleware/logs"
)

// PhonebookEntry represents a phonebook contact from cti_phonebook table.
type PhonebookEntry struct {
	ID             int64
	OwnerID        string
	Type           string
	HomeEmail      string
	WorkEmail      string
	HomePhone      string
	WorkPhone      string
	CellPhone      string
	Fax            string
	Title          string
	Company        string
	Notes          string
	Name           string
	HomeStreet     string
	HomePOB        string
	HomeCity       string
	HomeProvince   string
	HomePostalCode string
	HomeCountry    string
	WorkStreet     string
	WorkPOB        string
	WorkCity       string
	WorkProvince   string
	WorkPostalCode string
	WorkCountry    string
	URL            string
	Extension      string
	SpeedDialNum   string
}

var batchInsertPhonebookEntriesFunc = batchInsertPhonebookEntries

// SetBatchInsertPhonebookEntriesFuncForTest allows tests to override the batch insert behavior.
func SetBatchInsertPhonebookEntriesFuncForTest(fn func(context.Context, []*PhonebookEntry) (int, int, error)) func() {
	previous := batchInsertPhonebookEntriesFunc
	if fn == nil {
		batchInsertPhonebookEntriesFunc = batchInsertPhonebookEntries
	} else {
		batchInsertPhonebookEntriesFunc = fn
	}
	return func() {
		batchInsertPhonebookEntriesFunc = previous
	}
}

// BatchInsertPhonebookEntries inserts multiple phonebook entries in a transaction.
func BatchInsertPhonebookEntries(ctx context.Context, entries []*PhonebookEntry) (int, int, error) {
	return batchInsertPhonebookEntriesFunc(ctx, entries)
}

func batchInsertPhonebookEntries(ctx context.Context, entries []*PhonebookEntry) (int, int, error) {
	if len(entries) == 0 {
		return 0, 0, nil
	}

	database := db.GetDB()
	if database == nil {
		return 0, len(entries), errors.New("database not initialized")
	}

	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback()

	query := `
		INSERT INTO cti_phonebook (
			owner_id, type, homeemail, workemail, homephone, workphone, cellphone, fax,
			title, company, notes, name, homestreet, homepob, homecity, homeprovince,
			homepostalcode, homecountry, workstreet, workpob, workcity, workprovince,
			workpostalcode, workcountry, url, extension, speeddial_num
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	successful := 0
	failed := 0

	for _, entry := range entries {
		_, err := tx.ExecContext(ctx, query,
			entry.OwnerID, entry.Type, entry.HomeEmail, entry.WorkEmail, entry.HomePhone,
			entry.WorkPhone, entry.CellPhone, entry.Fax, entry.Title, entry.Company, entry.Notes,
			entry.Name, entry.HomeStreet, entry.HomePOB, entry.HomeCity, entry.HomeProvince,
			entry.HomePostalCode, entry.HomeCountry, entry.WorkStreet, entry.WorkPOB,
			entry.WorkCity, entry.WorkProvince, entry.WorkPostalCode, entry.WorkCountry,
			entry.URL, entry.Extension, entry.SpeedDialNum,
		)
		if err != nil {
			logs.Log("[ERROR][PHONEBOOK] Failed to insert entry for " + entry.Name + ": " + err.Error())
			failed++
		} else {
			successful++
		}
	}

	err = tx.Commit()
	if err != nil {
		return 0, len(entries), err
	}

	return successful, failed, nil
}
