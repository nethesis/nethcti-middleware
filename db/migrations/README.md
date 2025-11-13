# Database Migrations

This directory contains database migration scripts for the nethcti-middleware backend.

## Overview

Migrations are versioned SQL scripts that allow you to evolve your database schema over time while keeping track of changes. Each migration is a forward-only operation.

## Available Migrations

### 001 - Add Phone Field Indexes
**File**: `001_add_phone_indexes.sql`
**Description**: Adds indexes to all phone-related fields (homephone, workphone, cellphone, fax, extension) in the cti_phonebook table for improved query performance.
**Status**: Ready to apply

## Usage

### Prerequisites

1. Set your database connection parameters (or use environment variables):
   ```bash
   export PHONEBOOK_MARIADB_HOST=127.0.0.1
   export PHONEBOOK_MARIADB_PORT=3306
   export PHONEBOOK_MARIADB_USER=root
   export PHONEBOOK_MARIADB_PASSWORD=root
   export PHONEBOOK_MARIADB_DATABASE=nethcti3
   ```

2. Ensure Docker or Podman is installed and running:
   ```bash
   # Check Docker
   docker --version
   
   # OR check Podman
   podman --version
   ```

**Note**: You don't need MariaDB client (`mysql`) installed locally - the script uses containers with host networking to run database commands.

### Running Migrations

#### Direct Script Usage
From the migrations directory:
```bash
# Apply migration 001
./run_migration.sh 001 apply

# Check if migration 001 is applied
./run_migration.sh 001 status
```

### Migration Script Features

- ✅ **Containerized**: Uses Docker/Podman with host networking for MariaDB client commands
- ✅ **No Dependencies**: No need to install `mysql` locally
- ✅ **Transactional**: All changes applied in database transactions
- ✅ **Idempotent**: Safe to run multiple times
- ✅ **Tracked**: Migration status recorded in `schema_migrations` table
- ✅ **Verified**: Built-in verification of successful application
- ✅ **Checksums**: File integrity verification
- ✅ **Colored Output**: Easy-to-read console output
- ✅ **Auto-Detection**: Automatically detects Docker or Podman

## Migration Tracking

The system creates a `schema_migrations` table to track applied migrations:

```sql
CREATE TABLE schema_migrations (
    migration_number VARCHAR(10) PRIMARY KEY,
    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    description TEXT,
    checksum VARCHAR(64)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3;
```

## Safety Notes

⚠️ **Important Considerations**:

1. **Backup First**: Always backup your database before running migrations in production
2. **Test Environment**: Test migrations in a staging environment first
3. **Forward Only**: Migrations are not reversible - ensure thorough testing before applying

## Manual Migration (Alternative)

If you prefer to run migrations manually using containers:

```bash
# Using Docker
docker run --rm --network=host -v "$(pwd):/migrations:ro" mariadb:10.8.2 \
  mysql -h127.0.0.1 -uroot -proot nethcti3 < 001_your_migration.sql

# Using Podman
podman run --rm --network=host -v "$(pwd):/migrations:ro" mariadb:10.8.2 \
  mysql -h127.0.0.1 -uroot -proot nethcti3 < 001_your_migration.sql
```

## Troubleshooting

### Common Issues

**Database Connection Error**:
- Verify database environment variables are correctly set
- Test connection: `./run_migration.sh 001 status` (will test connection)

**Permission Error**:
- Ensure database user has necessary permissions
- Migrations require ability to create/drop tables, indexes, and columns

**Migration Already Applied**:
- Check status: `./run_migration.sh 001 status`
- Migrations are idempotent and can be safely re-run

## Development

### Adding New Migrations

1. Create new migration file with incremented number:
   - `001_your_migration_name.sql`

2. Test thoroughly in development environment

3. Document the migration in this README under "Available Migrations"

### Example Migration

**Migration** (`001_add_user_status.sql`):
```sql
-- Migration 001: Add status column to cti_phonebook
-- Description: Adds a status column to track phonebook entry state

ALTER TABLE cti_phonebook ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'active';
CREATE INDEX IF NOT EXISTS idx_phonebook_status ON cti_phonebook(status);
```
