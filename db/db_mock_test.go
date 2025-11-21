package db

import (
	"database/sql"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/require"

	"github.com/nethesis/nethcti-middleware/configuration"
)

func TestInitWithMockDB(t *testing.T) {
	mockDB, mock, cleanup := newMockDB(t)
	defer cleanup()

	mock.ExpectPing()
	mock.ExpectExec(`(?s).*CREATE TABLE IF NOT EXISTS cti_phonebook.*`).WillReturnResult(sqlmock.NewResult(0, 0))
	// the repository contains a no-op/comment upgrade.sql; expect it to be executed (no-op)
	mock.ExpectExec(`(?s).*No upgrade statements.*`).WillReturnResult(sqlmock.NewResult(0, 0))

	oldOpen := sqlOpenFunc
	sqlOpenFunc = func(driverName, dataSourceName string) (*sql.DB, error) {
		return mockDB, nil
	}
	defer func() { sqlOpenFunc = oldOpen }()

	prevConfig := configuration.Config
	configuration.Config = configuration.Configuration{
		PhonebookMariaDBUser:     "user",
		PhonebookMariaDBPassword: "pass",
		PhonebookMariaDBHost:     "127.0.0.1",
		PhonebookMariaDBPort:     "3306",
		PhonebookMariaDBDatabase: "nethcti3",
	}
	defer func() { configuration.Config = prevConfig }()

	prevDB := DB
	defer func() { DB = prevDB }()

	require.NoError(t, Init())
	require.NoError(t, mock.ExpectationsWereMet())
	require.NotNil(t, DB)

	Close()
}

func TestHealthCheckUsesDBPing(t *testing.T) {
	mockDB, mock, cleanup := newMockDB(t)
	defer cleanup()

	prevDB := DB
	defer func() { DB = prevDB }()

	DB = mockDB
	mock.ExpectPing()

	require.NoError(t, HealthCheck())
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestCloseClosesUnderlyingDB(t *testing.T) {
	mockDB, mock, cleanup := newMockDB(t)
	defer cleanup()

	prevDB := DB
	defer func() { DB = prevDB }()

	DB = mockDB
	mock.ExpectClose()

	require.NoError(t, Close())
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestCloseReturnsNilWhenNoDB(t *testing.T) {
	prevDB := DB
	defer func() { DB = prevDB }()
	DB = nil
	require.NoError(t, Close())
}

func TestInitOpenError(t *testing.T) {
	oldOpen := sqlOpenFunc
	defer func() { sqlOpenFunc = oldOpen }()
	sqlOpenFunc = func(_, _ string) (*sql.DB, error) {
		return nil, errors.New("boom")
	}
	cleanupConfig := applyTestConfig()
	defer cleanupConfig()

	prevDB := DB
	defer func() { DB = prevDB }()

	require.ErrorContains(t, Init(), "boom")
}

func TestInitPingError(t *testing.T) {
	mockDB, mock, cleanup := newMockDB(t)
	defer cleanup()

	mock.ExpectPing().WillReturnError(errors.New("ping fail"))

	oldOpen := sqlOpenFunc
	sqlOpenFunc = func(_, _ string) (*sql.DB, error) {
		return mockDB, nil
	}
	defer func() { sqlOpenFunc = oldOpen }()

	cleanupConfig := applyTestConfig()
	defer cleanupConfig()

	prevDB := DB
	defer func() { DB = prevDB }()

	require.ErrorContains(t, Init(), "ping fail")
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestInitCreateSchemaError(t *testing.T) {
	mockDB, mock, cleanup := newMockDB(t)
	defer cleanup()

	mock.ExpectPing()
	mock.ExpectExec(`(?s).*CREATE TABLE IF NOT EXISTS cti_phonebook.*`).WillReturnError(errors.New("exec fail"))

	oldOpen := sqlOpenFunc
	sqlOpenFunc = func(_, _ string) (*sql.DB, error) {
		return mockDB, nil
	}
	defer func() { sqlOpenFunc = oldOpen }()

	cleanupConfig := applyTestConfig()
	defer cleanupConfig()

	prevDB := DB
	defer func() { DB = prevDB }()

	require.ErrorContains(t, Init(), "exec fail")
	require.NoError(t, mock.ExpectationsWereMet())
}

func newMockDB(t *testing.T) (*sql.DB, sqlmock.Sqlmock, func()) {
	db, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
	require.NoError(t, err)
	return db, mock, func() { db.Close() }
}

func applyTestConfig() func() {
	prev := configuration.Config
	configuration.Config = configuration.Configuration{
		PhonebookMariaDBUser:     "user",
		PhonebookMariaDBPassword: "pass",
		PhonebookMariaDBHost:     "127.0.0.1",
		PhonebookMariaDBPort:     "3306",
		PhonebookMariaDBDatabase: "nethcti3",
	}
	return func() { configuration.Config = prev }
}
