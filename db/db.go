/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package db

import (
	"context"
	"database/sql"
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

// Init initializes the database connection pool with the configured MariaDB settings.
// It performs health checks and creates necessary schema.
func Init() error {
	dsn := fmt.Sprintf(
		"%s:%s@tcp(%s:%s)/%s?parseTime=true",
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
	err = createSchema()
	if err != nil {
		logs.Log("[CRITICAL][DB] Failed to create schema: " + err.Error())
		return err
	}

	return nil
}

// Close gracefully closes the database connection pool.
func Close() error {
	if DB != nil {
		return DB.Close()
	}
	return nil
}

// createSchema creates the necessary database schema for the middleware.
func createSchema() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Create phonebook table
	createPhonebookTable := `
	CREATE TABLE IF NOT EXISTS cti_phonebook (
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
		extension varchar(255) DEFAULT NULL,
		speeddial_num varchar(255) DEFAULT NULL,
		PRIMARY KEY (id),
		KEY owner_idx (owner_id),
		KEY wemail_idx (workemail),
		KEY hemail_idx (homeemail),
		KEY name_idx (name),
		KEY hphone_idx (homephone),
		KEY wphone_idx (workphone),
		KEY cphone_idx (cellphone),
		KEY extension_idx (extension),
		KEY fax_idx (fax),
		KEY company_idx (company)
	) ENGINE=MyISAM DEFAULT CHARSET=utf8mb3
	`

	_, err := DB.ExecContext(ctx, createPhonebookTable)
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
