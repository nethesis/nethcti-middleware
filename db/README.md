# Database initialization (cti_phonebook)

This file briefly documents how the `db` package initializes the MariaDB connection and applies schema SQL included in the repository.

Paths
-----
- `db/create.sql` — embedded initial schema (creates table `cti_phonebook`).
- `db/migrations/` — directory containing versioned database migrations for schema updates.

Behavior (short)
-----------------
- `db.Init()` builds a DSN from configuration and opens a connection pool.
- It verifies connectivity with `PingContext`.
- It executes `db/create.sql` to ensure the initial schema exists.
- Schema updates are applied via migrations (see `db/migrations/README.md`).

Key details
-----------
- The DSN includes `parseTime=true` and `multiStatements=true` so multi-statement SQL can run.
- The package uses an indirection (`sqlOpenFunc`) so tests can provide a mock DB without changing production code.
- Default env vars are provided for local testing, but set explicit values in production.

Environment variables (used to build DSN)
----------------------------------------
- `PHONEBOOK_MARIADB_HOST` (default: `localhost`)
- `PHONEBOOK_MARIADB_PORT` (default: `3306`)
- `PHONEBOOK_MARIADB_USER` (default: `root`)
- `PHONEBOOK_MARIADB_PASSWORD` (default: `root` in local/test)
- `PHONEBOOK_MARIADB_DATABASE` (default: `nethcti3`)

Testing
-------
- Unit tests for the package run with `go test ./db`.
- Integration tests that exercise the real DB require a running MariaDB instance (see `agents.md` for a Podman/Docker command).

Troubleshooting
---------------
- "Failed to ping database": verify the DB server is running and reachable.
- "Failed to create schema": check SQL compatibility with your MariaDB version.

Schema Migrations
-----------------
Database schema changes after the initial creation are managed through versioned migrations.

**Adding new migrations:**
1. Create a new migration file in `db/migrations/` with an incremented number (e.g., `001_add_column.sql`)
2. Run the migration using the migration script: `cd db/migrations && ./run_migration.sh 001 apply`
3. Document the migration in `db/migrations/README.md`

See `db/migrations/README.md` for detailed migration instructions and examples.

That's it — keep `db/create.sql` in version control for initial schema, and add migrations in `db/migrations/` for schema changes.
