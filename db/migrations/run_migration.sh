#!/bin/bash

# Database Migration Runner Script (Containerized)
# Usage: ./run_migration.sh [migration_number] [action]
#
# Examples:
#   ./run_migration.sh 001 apply    # Apply migration 001
#   ./run_migration.sh 001 status   # Check migration status

set -e  # Exit on any error

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MIGRATION_DIR="$SCRIPT_DIR"

# Container configuration
CONTAINER_ENGINE=""
MARIADB_IMAGE="mariadb:10.8.2"

# Database configuration from environment
DB_HOST="${PHONEBOOK_MARIADB_HOST:-127.0.0.1}"
DB_PORT="${PHONEBOOK_MARIADB_PORT:-3306}"
DB_USER="${PHONEBOOK_MARIADB_USER:-root}"
DB_PASSWORD="${PHONEBOOK_MARIADB_PASSWORD:-root}"
DB_NAME="${PHONEBOOK_MARIADB_DATABASE:-nethcti3}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Detect container engine (Docker or Podman)
detect_container_engine() {
    if command -v docker >/dev/null 2>&1; then
        CONTAINER_ENGINE="docker"
        log_info "Using Docker as container engine"
    elif command -v podman >/dev/null 2>&1; then
        CONTAINER_ENGINE="podman"
        log_info "Using Podman as container engine"
    else
        log_error "Neither Docker nor Podman found. Please install one of them."
        exit 1
    fi
}

# Check if migration file exists
check_migration_file() {
    local migration_number=$1
    local migration_file="${MIGRATION_DIR}/${migration_number}_*.sql"
    
    # Find the migration file
    local found_files=$(ls ${migration_file} 2>/dev/null | wc -l)
    
    if [ "$found_files" -eq 0 ]; then
        log_error "Migration file not found: ${migration_number}_*.sql"
        exit 1
    fi
}

# Run mysql command in container
run_mysql() {
    local sql_command="$1"
    local input_file="$2"

    if [ -n "$input_file" ]; then
        # Run with input file
        $CONTAINER_ENGINE run --rm -i \
            --network=host \
            -v "$MIGRATION_DIR:/migrations:ro" \
            "$MARIADB_IMAGE" \
            mysql -h"$DB_HOST" -P"$DB_PORT" -u"$DB_USER" -p"$DB_PASSWORD" "$DB_NAME" \
            < "$input_file" 2>&1 | grep -v "Emulate Docker CLI"
    else
        # Run with SQL command
        $CONTAINER_ENGINE run --rm -i \
            --network=host \
            "$MARIADB_IMAGE" \
            mysql -h"$DB_HOST" -P"$DB_PORT" -u"$DB_USER" -p"$DB_PASSWORD" "$DB_NAME" \
            -e "$sql_command" 2>&1 | grep -v "Emulate Docker CLI"
    fi
}

# Run mysql command and capture output
run_mysql_output() {
    local sql_command="$1"
    local flags="$2"

    local temp_output=$(mktemp)
    if $CONTAINER_ENGINE run --rm -i \
        --network=host \
        "$MARIADB_IMAGE" \
        mysql -h"$DB_HOST" -P"$DB_PORT" -u"$DB_USER" -p"$DB_PASSWORD" "$DB_NAME" \
        $flags -e "$sql_command" 2>&1 | grep -v "Emulate Docker CLI" > "$temp_output"; then
        # Success: return output
        cat "$temp_output"
        rm "$temp_output"
        return 0
    else
        # Error: show all output and exit with error
        cat "$temp_output"
        rm "$temp_output"
        return 1
    fi
}

# Create migrations table if it doesn't exist
create_migrations_table() {
    log_info "Creating migrations table if it doesn't exist..."
    run_mysql "CREATE TABLE IF NOT EXISTS schema_migrations (
        migration_number VARCHAR(10) PRIMARY KEY,
        applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        description TEXT,
        checksum VARCHAR(64)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3;" > /dev/null
    log_success "Migrations table ready"
}

# Calculate file checksum
get_file_checksum() {
    local file=$1
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$file" | cut -d' ' -f1
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$file" | cut -d' ' -f1
    else
        log_warning "No checksum utility found, using file size"
        stat -f%z "$file" 2>/dev/null || stat -c%s "$file"
    fi
}

# Check migration status
check_migration_status() {
    local migration_number=$1

    create_migrations_table || return 1

    local count_output
    if ! count_output=$(run_mysql_output "SELECT COUNT(*) FROM schema_migrations WHERE migration_number = '$migration_number';" "-sN"); then
        log_error "Failed to check migration status"
        return 1
    fi

    local count=$(echo "$count_output" | xargs)

    # Check if count is a number
    if ! [[ "$count" =~ ^[0-9]+$ ]]; then
        log_error "Invalid response from database: $count"
        return 1
    fi

    if [ "$count" -eq 1 ]; then
        local applied_at_output
        if ! applied_at_output=$(run_mysql_output "SELECT applied_at FROM schema_migrations WHERE migration_number = '$migration_number';" "-sN"); then
            log_error "Failed to get migration timestamp"
            return 1
        fi
        local applied_at=$(echo "$applied_at_output" | xargs)
        log_success "Migration $migration_number is applied (applied at: $applied_at)"
        return 0
    else
        log_info "Migration $migration_number is not applied"
        return 1
    fi
}

# Apply migration
apply_migration() {
    local migration_number=$1
    
    # Find the migration file
    local migration_file=$(ls ${MIGRATION_DIR}/${migration_number}_*.sql 2>/dev/null | head -1)
    
    if [ -z "$migration_file" ]; then
        log_error "Migration file not found for number: $migration_number"
        return 1
    fi

    # Extract description from filename
    local filename=$(basename "$migration_file")
    local description=$(echo "$filename" | sed -E 's/^[0-9]+_(.*)\.sql$/\1/' | tr '_' ' ')

    # Check if already applied
    if check_migration_status "$migration_number" > /dev/null 2>&1; then
        log_warning "Migration $migration_number is already applied"
        return 0
    fi

    log_info "Applying migration $migration_number: $description"

    # Calculate checksum
    local checksum=$(get_file_checksum "$migration_file")

    # Read the migration file content
    local migration_content=$(cat "$migration_file")
    
    # Create temporary transaction script
    local temp_script=$(mktemp)
    cat > "$temp_script" <<EOF
START TRANSACTION;

-- Apply the migration
$migration_content

-- Record migration
INSERT INTO schema_migrations (migration_number, description, checksum)
VALUES ('$migration_number', '$description', '$checksum');

COMMIT;
EOF

    # Apply migration in container
    local output
    if output=$($CONTAINER_ENGINE run --rm -i \
        --network=host \
        "$MARIADB_IMAGE" \
        mysql -h"$DB_HOST" -P"$DB_PORT" -u"$DB_USER" -p"$DB_PASSWORD" "$DB_NAME" \
        < "$temp_script" 2>&1 | grep -v "Emulate Docker CLI"); then
        rm "$temp_script"
        log_success "Migration $migration_number applied successfully"
    else
        echo "$output"
        rm "$temp_script"
        log_error "Failed to apply migration $migration_number"
        return 1
    fi
}

# Show usage
show_usage() {
    echo "Database Migration Runner (Containerized)"
    echo ""
    echo "Usage: $0 [migration_number] [action]"
    echo ""
    echo "Actions:"
    echo "  apply      Apply the migration"
    echo "  status     Check migration status"
    echo ""
    echo "Examples:"
    echo "  $0 001 apply      # Apply migration 001"
    echo "  $0 001 status     # Check if migration 001 is applied"
    echo ""
    echo "Environment Variables:"
    echo "  PHONEBOOK_MARIADB_HOST      Database host (default: 127.0.0.1)"
    echo "  PHONEBOOK_MARIADB_PORT      Database port (default: 3306)"
    echo "  PHONEBOOK_MARIADB_USER      Database user (default: root)"
    echo "  PHONEBOOK_MARIADB_PASSWORD  Database password (default: root)"
    echo "  PHONEBOOK_MARIADB_DATABASE  Database name (default: nethcti3)"
    echo ""
    echo "Requirements:"
    echo "  - Docker or Podman must be installed"
    echo ""
    echo "Note: This script uses containers to run MariaDB client commands,"
    echo "      so you don't need to install mysql client locally."
}

# Main script
main() {
    if [ $# -ne 2 ]; then
        show_usage
        exit 1
    fi

    local migration_number=$1
    local action=$2

    log_info "Database Migration Runner (Containerized) - Migration $migration_number, Action: $action"

    detect_container_engine
    check_migration_file "$migration_number"

    case $action in
        "apply")
            apply_migration "$migration_number"
            ;;
        "status")
            check_migration_status "$migration_number"
            ;;
        *)
            log_error "Unknown action: $action"
            show_usage
            exit 1
            ;;
    esac
}

# Run main function
main "$@"
