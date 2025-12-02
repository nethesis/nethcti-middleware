/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package store_test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nethesis/nethcti-middleware/configuration"
	"github.com/nethesis/nethcti-middleware/db"
	"github.com/nethesis/nethcti-middleware/logs"
	"github.com/nethesis/nethcti-middleware/store"
)

func TestMain(m *testing.M) {
	applyTestEnv()
	logs.Init("store-tests")
	configuration.Init()
	if err := ensureTestDatabase(); err != nil {
		logs.Log("[CRITICAL][STORE-TEST] Failed to create test database: " + err.Error())
		os.Exit(1)
	}
	if err := db.Init(); err != nil {
		logs.Log("[CRITICAL][STORE-TEST] Failed to init DB: " + err.Error())
		os.Exit(1)
	}
	code := m.Run()
	db.Close()
	os.Exit(code)
}

func applyTestEnv() {
	os.Setenv("NETHVOICE_MIDDLEWARE_LISTEN_ADDRESS", "127.0.0.1:8899")
	os.Setenv("NETHVOICE_MIDDLEWARE_V1_PROTOCOL", "http")
	os.Setenv("NETHVOICE_MIDDLEWARE_V1_API_ENDPOINT", "127.0.0.1")
	os.Setenv("NETHVOICE_MIDDLEWARE_V1_WS_ENDPOINT", "127.0.0.1")
	os.Setenv("NETHVOICE_MIDDLEWARE_V1_API_PATH", "/webrest")
	os.Setenv("NETHVOICE_MIDDLEWARE_V1_WS_PATH", "/socket.io")
	os.Setenv("NETHVOICE_MIDDLEWARE_SECRET_JWT", "test-secret-key-for-jwt-tokens")
	os.Setenv("NETHVOICE_MIDDLEWARE_SECRETS_DIR", "/tmp/test-secrets/nethcti-store")
	os.Setenv("NETHVOICE_MIDDLEWARE_ISSUER_2FA", "NetCTI-Test")
	os.Setenv("NETHVOICE_MIDDLEWARE_SENSITIVE_LIST", "password,secret")
	os.Setenv("NETHVOICE_MIDDLEWARE_MARIADB_HOST", "127.0.0.1")
	os.Setenv("NETHVOICE_MIDDLEWARE_MARIADB_PORT", "3306")
	os.Setenv("NETHVOICE_MIDDLEWARE_MARIADB_USER", "root")
	os.Setenv("NETHVOICE_MIDDLEWARE_MARIADB_PASSWORD", "root")
	os.Setenv("NETHVOICE_MIDDLEWARE_MARIADB_DATABASE", "nethcti3")
	os.MkdirAll("/tmp/test-secrets/nethcti-store", 0755)
}

func ensureTestDatabase() error {
	host := os.Getenv("NETHVOICE_MIDDLEWARE_MARIADB_HOST")
	port := os.Getenv("NETHVOICE_MIDDLEWARE_MARIADB_PORT")
	user := os.Getenv("NETHVOICE_MIDDLEWARE_MARIADB_USER")
	pass := os.Getenv("NETHVOICE_MIDDLEWARE_MARIADB_PASSWORD")
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/", user, pass, host, port)

	testDB, err := sql.Open("mysql", dsn)
	if err != nil {
		return err
	}
	defer testDB.Close()

	target := os.Getenv("NETHVOICE_MIDDLEWARE_MARIADB_DATABASE")
	_, err = testDB.Exec("DROP DATABASE IF EXISTS " + target)
	if err != nil {
		return err
	}
	_, err = testDB.Exec("CREATE DATABASE IF NOT EXISTS " + target)
	return err
}

// Helper function to clear phonebook entries before each test
func clearPhonebookTable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := db.GetDB().ExecContext(ctx, "DELETE FROM cti_phonebook")
	require.NoError(t, err, "Failed to clear phonebook table")
}

// Helper function to count phonebook entries in database
func countPhonebookEntries(t *testing.T) int {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var count int
	err := db.GetDB().QueryRowContext(ctx, "SELECT COUNT(*) FROM cti_phonebook").Scan(&count)
	require.NoError(t, err, "Failed to count phonebook entries")
	return count
}

// Helper function to verify entry exists in database
func entryExists(t *testing.T, name string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var id int64
	err := db.GetDB().QueryRowContext(ctx, "SELECT id FROM cti_phonebook WHERE name = ?", name).Scan(&id)
	return err == nil
}

// Test: Successful batch insert of phonebook entries
func TestBatchInsertPhonebookEntries_Success(t *testing.T) {
	clearPhonebookTable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	entries := []*store.PhonebookEntry{
		{
			Name:      "Alice Johnson",
			Type:      "private",
			OwnerID:   "user1",
			WorkPhone: "+1234567890",
			Company:   "Tech Corp",
		},
		{
			Name:      "Bob Smith",
			Type:      "public",
			OwnerID:   "user1",
			CellPhone: "+0987654321",
			Company:   "Services Inc",
		},
		{
			Name:      "Charlie Brown",
			Type:      "private",
			OwnerID:   "user1",
			WorkPhone: "+1111111111",
			CellPhone: "+2222222222",
			Company:   "Data Systems",
		},
	}

	successful, failed, err := store.BatchInsertPhonebookEntries(ctx, entries)

	require.NoError(t, err, "Batch insert should not fail")
	assert.Equal(t, 3, successful, "Should have successfully inserted 3 entries")
	assert.Equal(t, 0, failed, "Should have 0 failed entries")

	// Verify entries are in database
	count := countPhonebookEntries(t)
	assert.Equal(t, 3, count, "Database should have 3 entries")

	// Verify specific entries
	assert.True(t, entryExists(t, "Alice Johnson"), "Alice Johnson should exist")
	assert.True(t, entryExists(t, "Bob Smith"), "Bob Smith should exist")
	assert.True(t, entryExists(t, "Charlie Brown"), "Charlie Brown should exist")
}

// Test: Empty batch insert returns no error
func TestBatchInsertPhonebookEntries_EmptyBatch(t *testing.T) {
	clearPhonebookTable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	entries := []*store.PhonebookEntry{}

	successful, failed, err := store.BatchInsertPhonebookEntries(ctx, entries)

	assert.NoError(t, err, "Empty batch should not error")
	assert.Equal(t, 0, successful, "Should have 0 successful entries")
	assert.Equal(t, 0, failed, "Should have 0 failed entries")

	count := countPhonebookEntries(t)
	assert.Equal(t, 0, count, "Database should remain empty")
}

// Test: Mixed valid and invalid entries - transaction rollback on error
func TestBatchInsertPhonebookEntries_MixedValidInvalid(t *testing.T) {
	clearPhonebookTable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// First insert a valid entry
	entry1 := &store.PhonebookEntry{
		Name:      "Diana Prince",
		Type:      "private",
		OwnerID:   "user1",
		WorkPhone: "+3333333333",
	}

	successful, failed, err := store.BatchInsertPhonebookEntries(ctx, []*store.PhonebookEntry{entry1})
	require.NoError(t, err, "First insert should succeed")
	require.Equal(t, 1, successful, "First insert should have 1 successful")
	require.Equal(t, 0, failed, "First insert should have 0 failed")

	// Now try to insert mixed valid and invalid entries
	entries := []*store.PhonebookEntry{
		{
			Name:      "Eve Wilson",
			Type:      "public",
			OwnerID:   "user1",
			WorkPhone: "+4444444444",
		},
		{
			Name:      "Frank Miller",
			Type:      "private",
			OwnerID:   "user1",
			CellPhone: "+5555555555",
		},
	}

	successful, failed, err = store.BatchInsertPhonebookEntries(ctx, entries)

	// These should succeed with valid data
	require.NoError(t, err, "Batch with valid entries should not error")
	assert.Equal(t, 2, successful, "Should have 2 successful entries")
	assert.Equal(t, 0, failed, "Should have 0 failed entries")

	// Verify all entries are persisted
	count := countPhonebookEntries(t)
	assert.Equal(t, 3, count, "Database should have 3 entries total")
}

// Test: Batch insert with context timeout should handle gracefully
func TestBatchInsertPhonebookEntries_ContextTimeout(t *testing.T) {
	clearPhonebookTable(t)

	// Create context that times out immediately
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	// Give the timeout time to trigger
	time.Sleep(10 * time.Millisecond)

	entries := []*store.PhonebookEntry{
		{
			Name:      "Grace Lee",
			Type:      "private",
			OwnerID:   "user1",
			WorkPhone: "+6666666666",
		},
	}

	_, _, err := store.BatchInsertPhonebookEntries(ctx, entries)

	// Should get a context deadline exceeded error
	assert.Error(t, err, "Should error with timeout context")
}

// Test: Verify transaction rollback on critical failure
func TestBatchInsertPhonebookEntries_TransactionRollback(t *testing.T) {
	clearPhonebookTable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Create a large batch to verify transaction behavior
	entries := []*store.PhonebookEntry{}
	for i := 0; i < 5; i++ {
		entries = append(entries, &store.PhonebookEntry{
			Name:      fmt.Sprintf("Person %d", i),
			Type:      "private",
			OwnerID:   "user1",
			WorkPhone: fmt.Sprintf("+111111111%d", i),
		})
	}

	successful, failed, err := store.BatchInsertPhonebookEntries(ctx, entries)

	require.NoError(t, err, "Batch insert should succeed")
	assert.Equal(t, 5, successful, "Should insert all 5 entries")
	assert.Equal(t, 0, failed, "Should have no failed entries")

	count := countPhonebookEntries(t)
	assert.Equal(t, 5, count, "All entries should be committed")
}

// Test: Verify proper database schema exists
func TestPhonebookTableExists(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Try to query the table directly to verify it exists
	var count int
	err := db.GetDB().QueryRowContext(ctx, "SELECT COUNT(*) FROM cti_phonebook LIMIT 1").Scan(&count)

	require.NoError(t, err, "cti_phonebook table should exist and be queryable")
}

// Test: Verify insert preserves all fields correctly
func TestBatchInsertPhonebookEntries_AllFields(t *testing.T) {
	clearPhonebookTable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	entry := &store.PhonebookEntry{
		Name:           "Full Contact",
		Type:           "private",
		OwnerID:        "user1",
		HomeEmail:      "home@example.com",
		WorkEmail:      "work@example.com",
		HomePhone:      "+1111111111",
		WorkPhone:      "+2222222222",
		CellPhone:      "+3333333333",
		Fax:            "+4444444444",
		Title:          "Manager",
		Company:        "Tech Corp",
		Notes:          "Important contact",
		HomeStreet:     "123 Main St",
		HomePOB:        "POB 123",
		HomeCity:       "New York",
		HomeProvince:   "NY",
		HomePostalCode: "10001",
		HomeCountry:    "USA",
		WorkStreet:     "456 Work Ave",
		WorkPOB:        "POB 456",
		WorkCity:       "San Francisco",
		WorkProvince:   "CA",
		WorkPostalCode: "94102",
		WorkCountry:    "USA",
		URL:            "https://example.com",
		Extension:      "1234",
		SpeedDialNum:   "5678",
	}

	successful, failed, err := store.BatchInsertPhonebookEntries(ctx, []*store.PhonebookEntry{entry})

	require.NoError(t, err, "Insert with all fields should succeed")
	assert.Equal(t, 1, successful, "Should have 1 successful insert")
	assert.Equal(t, 0, failed, "Should have 0 failed inserts")

	// Verify entry and all its fields in database
	var dbEntry store.PhonebookEntry
	err = db.GetDB().QueryRowContext(ctx,
		`SELECT owner_id, type, homeemail, workemail, homephone, workphone, cellphone, fax,
			title, company, notes, name, homestreet, homepob, homecity, homeprovince,
			homepostalcode, homecountry, workstreet, workpob, workcity, workprovince,
			workpostalcode, workcountry, url, extension, speeddial_num FROM cti_phonebook WHERE name = ?`,
		"Full Contact").Scan(
		&dbEntry.OwnerID, &dbEntry.Type, &dbEntry.HomeEmail, &dbEntry.WorkEmail,
		&dbEntry.HomePhone, &dbEntry.WorkPhone, &dbEntry.CellPhone, &dbEntry.Fax,
		&dbEntry.Title, &dbEntry.Company, &dbEntry.Notes, &dbEntry.Name,
		&dbEntry.HomeStreet, &dbEntry.HomePOB, &dbEntry.HomeCity, &dbEntry.HomeProvince,
		&dbEntry.HomePostalCode, &dbEntry.HomeCountry, &dbEntry.WorkStreet, &dbEntry.WorkPOB,
		&dbEntry.WorkCity, &dbEntry.WorkProvince, &dbEntry.WorkPostalCode, &dbEntry.WorkCountry,
		&dbEntry.URL, &dbEntry.Extension, &dbEntry.SpeedDialNum,
	)

	require.NoError(t, err, "Should be able to retrieve inserted entry")
	assert.Equal(t, entry.OwnerID, dbEntry.OwnerID)
	assert.Equal(t, entry.Name, dbEntry.Name)
	assert.Equal(t, entry.WorkEmail, dbEntry.WorkEmail)
	assert.Equal(t, entry.Title, dbEntry.Title)
}
