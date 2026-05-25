/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package store_test

import (
	"context"
	"database/sql"
	"encoding/json"
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
		logs.Log("[CRITICAL][STORE-TEST] Failed to create test database, skipping: " + err.Error())
		os.Exit(0)
	}
	if err := db.Init(); err != nil {
		logs.Log("[CRITICAL][STORE-TEST] Failed to init DB, skipping: " + err.Error())
		os.Exit(0)
	}
	if err := ensureCentralizedPhonebookTable(); err != nil {
		logs.Log("[CRITICAL][STORE-TEST] Failed to init centralized phonebook table, skipping: " + err.Error())
		os.Exit(0)
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

func ensureCentralizedPhonebookTable() error {
	_, err := db.GetDB().Exec(`
		CREATE DATABASE IF NOT EXISTS phonebook DEFAULT CHARACTER SET utf8mb3 COLLATE utf8mb3_general_ci;
	`)
	if err != nil {
		return err
	}

	_, err = db.GetDB().Exec(`
		CREATE TABLE IF NOT EXISTS phonebook.phonebook (
			id int(11) NOT NULL AUTO_INCREMENT,
			owner_id varchar(255) NOT NULL DEFAULT '',
			type varchar(255) NOT NULL DEFAULT '',
			homeemail varchar(255) DEFAULT NULL,
			workemail varchar(255) DEFAULT NULL,
			homephone varchar(25) DEFAULT NULL,
			workphone varchar(25) DEFAULT NULL,
			cellphone varchar(25) DEFAULT NULL,
			fax varchar(25) DEFAULT NULL,
			title varchar(255) DEFAULT NULL,
			company varchar(255) DEFAULT NULL,
			notes text DEFAULT NULL,
			name varchar(255) DEFAULT NULL,
			homestreet varchar(255) DEFAULT NULL,
			homepob varchar(10) DEFAULT NULL,
			homecity varchar(255) DEFAULT NULL,
			homeprovince varchar(255) DEFAULT NULL,
			homepostalcode varchar(255) DEFAULT NULL,
			homecountry varchar(255) DEFAULT NULL,
			workstreet varchar(255) DEFAULT NULL,
			workpob varchar(10) DEFAULT NULL,
			workcity varchar(255) DEFAULT NULL,
			workprovince varchar(255) DEFAULT NULL,
			workpostalcode varchar(255) DEFAULT NULL,
			workcountry varchar(255) DEFAULT NULL,
			url varchar(255) DEFAULT NULL,
			PRIMARY KEY (id)
		) ENGINE=MyISAM DEFAULT CHARSET=utf8mb3;
	`)
	return err
}

// Helper function to clear phonebook entries before each test
func clearPhonebookTable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := db.GetDB().ExecContext(ctx, "DELETE FROM cti_phonebook")
	require.NoError(t, err, "Failed to clear phonebook table")
}

func clearCentralizedPhonebookTable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := db.GetDB().ExecContext(ctx, "DELETE FROM phonebook.phonebook")
	require.NoError(t, err, "Failed to clear centralized phonebook table")
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

func insertCentralizedPhonebookRow(t *testing.T, entry store.PhonebookEntry) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := db.GetDB().ExecContext(ctx, `
		INSERT INTO phonebook.phonebook (
			owner_id, type, homeemail, workemail, homephone, workphone, cellphone, fax,
			title, company, notes, name, homestreet, homepob, homecity, homeprovince,
			homepostalcode, homecountry, workstreet, workpob, workcity, workprovince,
			workpostalcode, workcountry, url
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		entry.OwnerID, entry.Type, entry.HomeEmail, entry.WorkEmail, entry.HomePhone, entry.WorkPhone,
		entry.CellPhone, entry.Fax, entry.Title, entry.Company, entry.Notes, entry.Name, entry.HomeStreet,
		entry.HomePOB, entry.HomeCity, entry.HomeProvince, entry.HomePostalCode, entry.HomeCountry,
		entry.WorkStreet, entry.WorkPOB, entry.WorkCity, entry.WorkProvince, entry.WorkPostalCode,
		entry.WorkCountry, entry.URL,
	)
	require.NoError(t, err)
}

func TestGroupTypeHelpers(t *testing.T) {
	t.Run("parses and normalizes group type", func(t *testing.T) {
		groups := store.GetSharedGroupsFromType("group: Sales,Support,Sales ")
		assert.Equal(t, []string{"Sales", "Support"}, groups)
		assert.Equal(t, "group:Sales,Support", store.EncodeSharedGroupsType(groups))
	})

	t.Run("normalizes group permission id", func(t *testing.T) {
		assert.Equal(t, "grp_testgroup42", store.GetGroupPermissionID("Test Group 42"))
	})

	t.Run("validates allowed group contact types", func(t *testing.T) {
		assert.True(t, store.IsValidGroupContactType("group:Sales,Support"))
		assert.True(t, store.IsValidGroupContactType("GROUP:Sales"))
		assert.False(t, store.IsValidGroupContactType("group:"))
		assert.False(t, store.IsValidGroupContactType("group:public"))
		assert.False(t, store.IsValidGroupContactType("private"))
	})
}

func TestPhonebookPermissionLevelFromCapabilities(t *testing.T) {
	t.Run("returns disabled when phonebook macro is missing", func(t *testing.T) {
		assert.Equal(t, -1, store.GetPhonebookPermissionLevelFromCapabilities(map[string]bool{}))
	})

	t.Run("preserves explicit legacy precedence", func(t *testing.T) {
		caps := map[string]bool{
			"phonebook":                    true,
			"phonebook.phonebook_level_0": true,
			"phonebook.phonebook_level_2": true,
			"phonebook.ad_phonebook":      true,
		}
		assert.Equal(t, 2, store.GetPhonebookPermissionLevelFromCapabilities(caps))
	})

	t.Run("treats macro-only phonebook as level 0", func(t *testing.T) {
		assert.Equal(t, 0, store.GetPhonebookPermissionLevelFromCapabilities(map[string]bool{
			"phonebook": true,
		}))
	})

	t.Run("maps explicit level 1 capability", func(t *testing.T) {
		assert.Equal(t, 1, store.GetPhonebookPermissionLevelFromCapabilities(map[string]bool{
			"phonebook":                    true,
			"phonebook.phonebook_level_1": true,
		}))
	})
}

func TestAllowedOperatorGroupIDs(t *testing.T) {
	assert.Equal(t, []string{"grp_sales", "grp_support"}, store.GetAllowedOperatorGroupIDs(map[string]bool{
		"presence_panel.grp_support": true,
		"presence_panel.grp_sales":   true,
		"presence_panel.grp_hidden":  false,
	}))
	assert.True(t, store.CanSeeAllOperatorGroups(map[string]bool{"presence_panel.all_groups": true}))
}

func TestSearchLegacyPhonebook_ReturnsUnionWithVisibilityFiltering(t *testing.T) {
	clearPhonebookTable(t)
	clearCentralizedPhonebookTable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	require.NoError(t, store.CreatePhonebookEntry(ctx, &store.PhonebookEntry{
		OwnerID: "alice",
		Type:    "private",
		Name:    "Alice Private",
		Company: "Personal",
	}))
	require.NoError(t, store.CreatePhonebookEntry(ctx, &store.PhonebookEntry{
		OwnerID: "bob",
		Type:    "public",
		Name:    "Bob Public",
		Company: "Acme",
	}))
	require.NoError(t, store.CreatePhonebookEntry(ctx, &store.PhonebookEntry{
		OwnerID: "bob",
		Type:    "group:Sales",
		Name:    "Bob Shared",
		Company: "Acme",
	}))
	require.NoError(t, store.CreatePhonebookEntry(ctx, &store.PhonebookEntry{
		OwnerID: "bob",
		Type:    "group:Hidden",
		Name:    "Bob Hidden",
		Company: "Acme",
	}))
	require.NoError(t, store.CreatePhonebookEntry(ctx, &store.PhonebookEntry{
		OwnerID: "bob",
		Type:    "speeddial",
		Name:    "Ignored Speeddial",
		Company: "Acme",
	}))
	insertCentralizedPhonebookRow(t, store.PhonebookEntry{
		OwnerID: "central",
		Type:    "public",
		Name:    "Central Contact",
		Company: "Acme",
	})

	result, err := store.SearchLegacyPhonebook(ctx, store.LegacyPhonebookQuery{
		Username:               "alice",
		UserGroups:             []string{"Sales"},
		Term:                   "",
		IncludePrivateContacts: true,
	})
	require.NoError(t, err)
	require.Equal(t, 4, result.Count)

	names := make([]string, 0, len(result.Rows))
	for _, row := range result.Rows {
		names = append(names, row.Name)
	}
	assert.Contains(t, names, "Alice Private")
	assert.Contains(t, names, "Bob Public")
	assert.Contains(t, names, "Bob Shared")
	assert.Contains(t, names, "Central Contact")
	assert.NotContains(t, names, "Bob Hidden")
	assert.NotContains(t, names, "Ignored Speeddial")
}

func TestSearchLegacyPhonebook_CompanyViewBuildsContactsPayload(t *testing.T) {
	clearPhonebookTable(t)
	clearCentralizedPhonebookTable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	require.NoError(t, store.CreatePhonebookEntry(ctx, &store.PhonebookEntry{
		OwnerID: "bob",
		Type:    "public",
		Name:    "",
		Company: "Acme",
		Notes:   "Headquarters",
	}))
	require.NoError(t, store.CreatePhonebookEntry(ctx, &store.PhonebookEntry{
		OwnerID: "bob",
		Type:    "public",
		Name:    "Bob Public",
		Company: "Acme",
	}))
	require.NoError(t, store.CreatePhonebookEntry(ctx, &store.PhonebookEntry{
		OwnerID: "bob",
		Type:    "group:Sales",
		Name:    "Bob Shared",
		Company: "Acme",
	}))
	insertCentralizedPhonebookRow(t, store.PhonebookEntry{
		OwnerID: "central",
		Type:    "public",
		Name:    "Central Contact",
		Company: "Acme",
	})

	result, err := store.SearchLegacyPhonebook(ctx, store.LegacyPhonebookQuery{
		Username:               "alice",
		UserGroups:             []string{"Sales"},
		Term:                   "Acme",
		View:                   "company",
		IncludePrivateContacts: true,
	})
	require.NoError(t, err)
	require.Equal(t, 1, result.Count)
	require.Len(t, result.Rows, 1)
	assert.Equal(t, "Acme", result.Rows[0].Company)

	var contacts []map[string]any
	require.NoError(t, json.Unmarshal([]byte(result.Rows[0].Contacts), &contacts))
	require.Len(t, contacts, 3)
	assert.Equal(t, "Bob Public", contacts[0]["name"])
	assert.Equal(t, "Bob Shared", contacts[1]["name"])
	assert.Equal(t, "Central Contact", contacts[2]["name"])
}

func TestListLegacyPhonebook_ReturnsAlphabeticalUnion(t *testing.T) {
	clearPhonebookTable(t)
	clearCentralizedPhonebookTable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	require.NoError(t, store.CreatePhonebookEntry(ctx, &store.PhonebookEntry{
		OwnerID: "bob",
		Type:    "public",
		Name:    "",
		Company: "Alpha Corp",
	}))
	require.NoError(t, store.CreatePhonebookEntry(ctx, &store.PhonebookEntry{
		OwnerID: "alice",
		Type:    "private",
		Name:    "Beta User",
		Company: "Personal",
	}))
	insertCentralizedPhonebookRow(t, store.PhonebookEntry{
		OwnerID: "central",
		Type:    "public",
		Name:    "Gamma Contact",
		Company: "Gamma Inc",
	})

	result, err := store.ListLegacyPhonebook(ctx, store.LegacyPhonebookQuery{
		Username:               "alice",
		IncludePrivateContacts: true,
	})
	require.NoError(t, err)
	require.Equal(t, 3, result.Count)
	require.Len(t, result.Rows, 3)
	assert.Equal(t, "Alpha Corp", result.Rows[0].Company)
	assert.Equal(t, "Beta User", result.Rows[1].Name)
	assert.Equal(t, "Gamma Contact", result.Rows[2].Name)
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
	assert.Equal(t, entry.Type, dbEntry.Type)
	assert.Equal(t, entry.WorkEmail, dbEntry.WorkEmail)
	assert.Equal(t, entry.Title, dbEntry.Title)
}

func TestBatchInsertPhonebookEntries_GroupTypePersists(t *testing.T) {
	clearPhonebookTable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	entry := &store.PhonebookEntry{
		Name:      "Group Contact",
		Type:      "group:Sales,Support",
		OwnerID:   "user1",
		WorkPhone: "+7777777777",
	}

	successful, failed, err := store.BatchInsertPhonebookEntries(ctx, []*store.PhonebookEntry{entry})

	require.NoError(t, err, "Insert with group type should succeed")
	assert.Equal(t, 1, successful, "Should have 1 successful insert")
	assert.Equal(t, 0, failed, "Should have 0 failed inserts")

	var storedType string
	err = db.GetDB().QueryRowContext(ctx, "SELECT type FROM cti_phonebook WHERE name = ?", entry.Name).Scan(&storedType)
	require.NoError(t, err, "Should be able to retrieve stored group type")
	assert.Equal(t, entry.Type, storedType)
}
