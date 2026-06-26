-- nethcti-middleware: db/upgrade.sql
-- Idempotent upgrade scripts applied to pre-existing databases at startup.

-- Issue #7124: phonebook structure redesign. Add split name, role, social and
-- extra phone columns to cti_phonebook. MariaDB supports IF NOT EXISTS on both
-- ADD COLUMN and ADD INDEX, keeping this script safe to re-run on every boot.
USE nethcti3;

ALTER TABLE cti_phonebook
	ADD COLUMN IF NOT EXISTS firstname varchar(255) DEFAULT NULL,
	ADD COLUMN IF NOT EXISTS lastname varchar(255) DEFAULT NULL,
	ADD COLUMN IF NOT EXISTS job varchar(255) DEFAULT NULL,
	ADD COLUMN IF NOT EXISTS facebook varchar(255) DEFAULT NULL,
	ADD COLUMN IF NOT EXISTS instagram varchar(255) DEFAULT NULL,
	ADD COLUMN IF NOT EXISTS linkedin varchar(255) DEFAULT NULL,
	ADD COLUMN IF NOT EXISTS workphone2 varchar(25) DEFAULT NULL,
	ADD COLUMN IF NOT EXISTS cellphone2 varchar(25) DEFAULT NULL;

ALTER TABLE cti_phonebook
	ADD INDEX IF NOT EXISTS lastname_idx (lastname),
	ADD INDEX IF NOT EXISTS wphone2_idx (workphone2),
	ADD INDEX IF NOT EXISTS cphone2_idx (cellphone2);
