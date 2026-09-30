-- nethcti-middleware: db/upgrade.sql
USE nethcti3;

CREATE TABLE IF NOT EXISTS user_nethlink (
	user varchar(255) NOT NULL UNIQUE,
	extension varchar(255) NOT NULL,
	timestamp varchar(255) DEFAULT NULL,
	nethlink_version varchar(64) DEFAULT NULL,
	os_type varchar(32) DEFAULT NULL,
	os_release varchar(128) DEFAULT NULL,
	arch varchar(32) DEFAULT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8mb3;

ALTER TABLE user_nethlink
	ADD COLUMN IF NOT EXISTS nethlink_version varchar(64) DEFAULT NULL,
	ADD COLUMN IF NOT EXISTS os_type varchar(32) DEFAULT NULL,
	ADD COLUMN IF NOT EXISTS os_release varchar(128) DEFAULT NULL,
	ADD COLUMN IF NOT EXISTS arch varchar(32) DEFAULT NULL;
