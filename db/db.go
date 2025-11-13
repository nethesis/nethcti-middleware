/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package db

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/nethesis/nethcti-middleware/configuration"
	"github.com/nethesis/nethcti-middleware/logs"
)

var (
	DB          *sql.DB
	sqlOpenFunc = sql.Open
)

//go:embed create.sql
var createSchema string

// Init initializes the database connection pool with the configured MariaDB settings.
// It performs health checks and creates necessary schema.
func Init() error {
	dsn := fmt.Sprintf(
		"%s:%s@tcp(%s:%s)/%s?parseTime=true&multiStatements=true",
		configuration.Config.PhonebookMariaDBUser,
		configuration.Config.PhonebookMariaDBPassword,
		configuration.Config.PhonebookMariaDBHost,
		configuration.Config.PhonebookMariaDBPort,
		configuration.Config.PhonebookMariaDBDatabase,
	)

	var err error
	DB, err = sqlOpenFunc("mysql", dsn)
	if err != nil {
		logs.Log("[CRITICAL][DB] Failed to open database connection: " + err.Error())
		return err
	}

	// Configure connection pool
	DB.SetMaxOpenConns(25)
	DB.SetMaxIdleConns(5)
	DB.SetConnMaxLifetime(5 * time.Minute)

	// Test the connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = DB.PingContext(ctx)
	if err != nil {
		logs.Log("[CRITICAL][DB] Failed to ping database: " + err.Error())
		return err
	}

	logs.Log("[DB] Database connection established successfully")

	// Create schema if it doesn't exist
	err = loadCreateSchema()
	if err != nil {
		logs.Log("[CRITICAL][DB] Failed to create schema: " + err.Error())
		return err
	}

	logs.Log("[DB] Schema initialization complete. Run migrations from db/migrations/ for schema updates.")
	return nil
}

// Close gracefully closes the database connection pool.
func Close() error {
	if DB != nil {
		return DB.Close()
	}
	return nil
}

// loadCreateSchema creates the necessary database schema for the middleware.
func loadCreateSchema() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := DB.ExecContext(ctx, createSchema)
	if err != nil {
		return err
	}

	logs.Log("[DB] Schema created/verified successfully")
	return nil
}

// HealthCheck performs a health check on the database connection.
func HealthCheck() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	return DB.PingContext(ctx)
}
