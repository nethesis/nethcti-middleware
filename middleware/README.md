# Authorization & Profile Management

## Overview

The middleware uses a **JWT-based authorization system** where user profile data and all capabilities are loaded at startup and injected into JWT claims during login. Authorization checks are performed by examining the JWT claims, eliminating the need for runtime database lookups.

## Architecture

### Profile Loading (`store/profiles.go`)

The `store` package handles loading and caching profile/user data:

- `InitProfiles(profilesPath, usersPath)` - Called during startup to load all profiles and users from JSON files
- `GetUserProfile(username)` - Returns a user's profile with all capabilities
- `GetUserCapabilities(username)` - Returns just the capability map for a user

Files are loaded **once at startup** and remain in memory. To update profiles, restart the service.

### JWT Claims Injection

During login, the JWT middleware's `PayloadFunc` injects all profile and capability data into the JWT token.

Example JWT payload after login:
```json
{
  "id": "giacomo",
  "2fa": true,
  "otp_verified": false,
  "profile_id": "1",
  "profile_name": "Advanced",
  "phonebook.value": true,
  "phonebook.ad_phonebook": true,
  "phonebook.import": false
}
```

### Authorization Checks

The `RequireCapabilities()` middleware checks if required capabilities exist and are `true` in the JWT claims:

```go
api.POST("/phonebook/import", 
    middleware.RequireCapabilities("phonebook.ad_phonebook"), 
    methods.ImportPhonebookCSV)
```

This middleware:
1. Extracts the JWT claims from the request
2. Checks that each required capability is present and `true`
3. Denies access (HTTP 403) if any capability is missing or false

## Profile & User JSON Structure

### `profiles.json`

Defines available profiles with macro permissions and individual permissions:

```json
{
  "1": {
    "id": "1",
    "name": "Advanced",
    "macro_permissions": {
      "phonebook": {
        "value": true,
        "permissions": [
          {"id": "12", "name": "ad_phonebook", "value": true},
          {"id": "13", "name": "import", "value": false}
        ]
      }
    }
  }
}
```

Capabilities are generated as:
- `<macro>.<permission_name>` for each permission (e.g., `phonebook.ad_phonebook`)
- `<macro>.value` for each macro (e.g., `phonebook.value`)

### `users.json`

Maps usernames to profile IDs:

```json
{
  "giacomo": {"profile_id": "1"},
  "user2": {"profile_id": "2"}
}
```

## Environment Configuration

1. Set the file paths via environment variables:
   ```bash
   AUTH_PROFILES_PATH=/etc/nethcti/profiles.json
   AUTH_USERS_PATH=/etc/nethcti/users.json
   ```

2. Ensure both files exist with the JSON structures described above.

3. Verify file permissions:
   ```bash
   chown middleware:middleware /etc/nethcti/profiles.json /etc/nethcti/users.json
   chmod 0644 /etc/nethcti/profiles.json /etc/nethcti/users.json
   chmod 0755 /etc/nethcti
   ```

4. Restart the middleware:
   ```bash
   sudo systemctl restart nethcti-middleware.service
   ```

## Troubleshooting

### Authorization Denied

- Check logs for `[AUTHZ][DENIED]` entries showing which capability is missing
- Verify the user exists in `users.json` with the correct `profile_id`
- Verify the profile exists in `profiles.json` with the required capability defined

### Profile Loading Errors

- Check logs for `[AUTHZ][WARN] Failed to load profile` messages
- Ensure both JSON files are valid (use `jq` to validate)
- Verify file permissions allow the middleware process to read them

### Invalid JSON

- Use `jq` to validate the JSON structure:
  ```bash
  jq empty /etc/nethcti/profiles.json
  jq empty /etc/nethcti/users.json
  ```
- Keep backups of the JSON files; invalid JSON will prevent the profile from loading

## Testing

Unit tests for authorization are in `middleware/profile_test.go`:

```bash
go test -v ./middleware -run TestRequireCapabilities
```

These tests inject capabilities into JWT claims and verify the middleware correctly allows/denies access.
