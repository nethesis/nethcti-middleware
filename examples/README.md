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
