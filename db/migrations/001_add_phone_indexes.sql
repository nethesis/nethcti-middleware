-- Migration 001: Add indexes to phone fields in cti_phonebook
-- Description: Ensures all phone-related fields have indexes for improved query performance

USE nethcti3;

-- Add index to name if it doesn't exist
CREATE INDEX IF NOT EXISTS name_idx ON cti_phonebook(name);
