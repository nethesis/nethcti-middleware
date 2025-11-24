# Examples

This directory contains example files and helper scripts for testing and deploying the middleware.

## Files

- `profiles.json` - Example profile definitions with capabilities
- `users.json` - Example user-to-profile mappings
- `contacts.csv` - Example CSV file for phonebook import testing
- `import_phonebook_csv.sh` - Helper script to test the phonebook import endpoint

## Using profiles.json and users.json

For deployment and configuration instructions, see [`middleware/README.md`](../middleware/README.md).

These files define:
- **`profiles.json`**: Available profiles and their capabilities (macro permissions and individual permissions)
- **`users.json`**: User-to-profile mappings that link each user to a profile

Copy and adapt these files to your environment, then set the paths in environment variables:

```bash
export AUTH_PROFILES_PATH=/etc/nethcti/profiles.json
export AUTH_USERS_PATH=/etc/nethcti/users.json
```

Restart the middleware for changes to take effect.

## Import Helper: import_phonebook_csv.sh

This bash helper script tests the `/phonebook/import` endpoint.

### Usage

```bash
./examples/import_phonebook_csv.sh HOST USER PASS CSV_FILE
```

Arguments:
- `HOST`: Base URL of the API (e.g., `https://cti.nethserver.net`)
- `USER`: Username to log in with
- `PASS`: Password for the user
- `CSV_FILE`: Path to a CSV file to upload

### Example

```bash
./examples/import_phonebook_csv.sh https://cti.nethserver.net user1 "User1,1234" contacts.csv
```

### What the script does

1. Logs in to the server using `/api/login`
2. Extracts the JWT token from the login response (supports `token`, `data.token`, or `access_token` fields)
3. Uploads the CSV file as a `file` form field to `/api/phonebook/import` with `Authorization: Bearer <token>` header
4. Prints the HTTP status code and response body (pretty-printed with `jq` if available)

### Notes & Troubleshooting

- The script always performs a login; it does not accept precomputed tokens
- If login fails, the script prints headers and a response snippet for debugging
- Exit code is non-zero if the request returns a non-2xx HTTP status
- Supports both JSON and form-encoded login formats

## CSV Format

The phonebook import accepts CSV files with the following structure:

### Required Columns
- `name` - Contact name (required)

### Optional Columns

**Email:**
- `workemail`, `homeemail`

**Phone:**
- `workphone`, `homephone`, `cellphone`, `fax`, `extension`, `speeddial_num`

**Address:**
- `homestreet`, `homepob`, `homecity`, `homeprovince`, `homepostalcode`, `homecountry`
- `workstreet`, `workpob`, `workcity`, `workprovince`, `workpostalcode`, `workcountry`

**Other:**
- `type` - `private` or `public` (defaults to `private`)
- `title`, `company`, `notes`, `url`

### Error Reporting

The import endpoint returns structured JSON errors. Example:

```json
{
  "error_messages": [
    "Row 4: wrong number of fields",
    "Row 7: invalid phone format"
  ]
}
```

See `contacts.csv` for an example file.

## Security & Automation

- Avoid committing CSV files with sensitive personal data to the repository
- For automated deployments, use a programmatic client with service account credentials
- This script is intended for manual testing and debugging

