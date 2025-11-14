# Authorization Deployment Notes

## Environment configuration
1. Export the file locations before starting the service (for example in `/etc/default/nethcti-middleware` or the unit file):
   ```bash
   AUTH_PROFILES_PATH=/etc/nethcti/profiles.json
   AUTH_USERS_PATH=/etc/nethcti/users.json
   ```
2. Ensure both files exist and contain the structures described in `examples/profiles.json`/`examples/users.json`.
3. Restart the middleware so `configuration.Init()` picks up the new values. The manager reads the files once at startup and again whenever an `fsnotify` event triggers a reload.

## File ownership & permissions
- The running service needs read access to each JSON file and execute access to parent directories so `fsnotify` can follow events:
  ```bash
  chown middleware:middleware /etc/nethcti/profiles.json /etc/nethcti/users.json
  chmod 0644 /etc/nethcti/profiles.json /etc/nethcti/users.json
  chmod 0755 /etc/nethcti
  ```
- If the service runs as a dedicated user (e.g., `nethcti`), ensure it is the owner or belongs to the owning group. Watchers open the file to read it, so lacking read permission causes reload failures logged as `[AUTHZ] reload failed`.

## Watcher behavior
- `authz.NewManager` creates two `fsnotify` watchers (one per file) before booting the router. These watchers keep the file handles alive, so the files should not be deleted in place; if you replace them atomically, the watcher detects the `Remove` event and re-adds the new path.
- Most editors save by writing to a temp file and renaming it, which triggers the `Rename` event; the manager attempts to re-watch up to three times with a short backoff, so ensure the middleware retains permission to add the path.
- Avoid placing those files on non-local filesystems that do not support `inotify`/`fsnotify` events (NFS, CIFS) unless the transport emits reliable events.

## Systemd/service recommendation
- When running under `systemd`, drop the environment file into `/etc/sysconfig` or `/etc/default`, then reload the unit and restart:
  ```bash
  sudo systemctl daemon-reload
  sudo systemctl restart nethcti-middleware.service
  ```
- Use `journalctl -u nethcti-middleware -f` to confirm the `[AUTHZ] loaded` logs after startup and to catch reload errors triggered by permission problems.

## Checks & troubleshooting
- If the middleware refuses requests, watch the logs for `[AUTHZ][DENIED]` entries and ensure the user referenced in the JWT exists in `users.json` with the right `profile_id`.
- To verify watcher access, touch the file:
  ```bash
  touch /etc/nethcti/profiles.json
  ```
  If permissions are sufficient, the service logs `[AUTHZ] loaded` (profiles or users) shortly afterward.
- Keep backups of the JSON files, because invalid JSON will cause the reload to fail and the previous configuration stays in memory (the manager only swaps on successful unmarshalling).

## Import helper: import_phonebook_csv.sh

This repository includes a small bash helper script to exercise the `/phonebook/import` endpoint: `examples/import_phonebook_csv.sh`.

Usage
-----
The script requires four positional arguments:

- HOST: Base URL of the API (for example `https://cti.nethserver.net`)
- USER: Username to log in with
- PASS: Password for the user
- CSV_FILE: Path to a CSV file to upload

Example
-------
```bash
./examples/import_phonebook_csv.sh https://cti.nethserver.net user1 "User1,1234" contacts.csv
```

What the script does
--------------------
- Logs in to the server using the single, fixed endpoint `/api/login` (the script will not use any other login endpoint).
- Attempts to extract a JWT token from the login response (supports JSON responses with `token`, `data.token` or `access_token` fields).
- Uploads the provided CSV file as a `file` form field to `/api/phonebook/import` with the `Authorization: Bearer <token>` header.
- Prints the HTTP status code and the response body (pretty-printed with `jq` if available).

Script notes & troubleshooting
------------------------------
- The script does not accept a precomputed token; it always performs a login to obtain a fresh JWT. This avoids reusing stale tokens.
- If login fails, the script prints response headers and a short snippet of the body to help debugging.
- The script will exit with a non-zero code if the request returns a non-2xx HTTP status.
- The script tries two POST formats for login: JSON and form-encoded, to support different server behaviors.

CSV format
----------
The CSV should have a header row. The `name` column is required. Supported columns include (case-insensitive):

- name (required)
- type (private|public, defaults to private)
- workemail, homeemail
- workphone, homephone, cellphone, fax
- title, company, notes
- homestreet, homepob, homecity, homeprovince, homepostalcode, homecountry
- workstreet, workpob, workcity, workprovince, workpostalcode, workcountry
- url, extension, speeddial_num

Error reporting
---------------
The import endpoint reports structured JSON. Example error entries look like:

```
"error_messages": [
  "Row 4: wrong number of fields"
]
```

Security & automation
---------------------
- Avoid committing CSV files with sensitive personal data to the repository.
- For automated runs (CI), prefer a programmatic client that injects a known token or uses a service account; this script is intended for manual testing and debugging.

