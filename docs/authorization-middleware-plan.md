# Authorization Middleware Plan

## 1. Objectives & Scope
- Authorize access to user-facing APIs based on profiles and per-endpoint rules without hitting external services.
- Load `profiles.json` and `users.json` from configurable paths at startup, keep them hot-reloaded, and expose an in-memory lookup for middleware decisions.
- Allow Gin routes to declare the profile capabilities they require so the middleware can allow/deny requests consistently.

## 2. Configuration Surface
| Config Field | Source | Default | Notes |
| --- | --- | --- | --- |
| `ProfilesConfigPath` | env `AUTH_PROFILES_PATH` | `/etc/nethcti/profiles.json` | Absolute path to the JSON describing profiles & permissions. Required at runtime. |
| `UsersConfigPath` | env `AUTH_USERS_PATH` | `/etc/nethcti/users.json` | Absolute path to the JSON map of username → profile_id. Required at runtime. |

Both paths will be read during `configuration.Init()`. The process should fail fast when files are missing or invalid.

## 3. Data Model & Validation
- **Profiles:** mirror `examples/profiles.json` structure. Normalize into:
  ```go
  type Permission struct { Macro string; ID string; Name string; Value bool }
  type Profile struct { ID, Name string; MacroPermissions map[string]MacroPermission; Routes map[string]bool }
  ```
  Collapse nested `macro_permissions` and `permissions` arrays into flattened lookups keyed by `macro.permission`. Precompute a `Capabilities` set like `phonebook.read=true`.
- **Users:** parse `users.json` into `map[string]UserProfileRef` where each entry stores the `profile_id` and optionally derived cache of capabilities.
- **Rules:** represent each protected endpoint as `AuthorizationRule{ PathPattern, Methods, RequiredCapabilities []string, AllowProfiles []string }`. Support wildcard paths via `path.Match` or Regex.
- **Validation Pipeline:**
  1. Load raw JSON.
  2. Validate schema (required keys, boolean values). Reject/ log with precise line info.
  3. Build normalized structs, ensuring every `users.profile_id` exists in `profiles`.
  4. Atomically swap the shared cache when both files parse correctly to avoid partial states.

Use `sync.RWMutex` and version counters so middleware reads are lock-free (read-only locks) and reloads are atomic.

## 4. File Watching & Hot Reload
- Use `github.com/fsnotify/fsnotify` to watch both configured paths.
- On startup:
  1. Load files sequentially with `loadProfiles()` and `loadUsers()`.
  2. Start watchers in a dedicated goroutine with context cancellation on shutdown.
  3. Debounce events (e.g., `time.After(500 * time.Millisecond)`) because editors may emit multiple update signals.
  4. On change, re-run the validation pipeline; if parsing fails, keep the previous good snapshot and log an error.
- Provide a `Stop()` hook triggered from `main.go` (e.g., via `context.WithCancel`) to close watchers gracefully.

## 5. Middleware Behavior
1. **Registration:** expose `middleware.Authorization(required AuthorizationRequirement)` returning a `gin.HandlerFunc`. Integrate during router setup alongside JWT middleware.
2. **Request Flow:**
   - Extract username from JWT claims (already available in `middleware.InstanceJWT`).
   - Look up `user := cache.Users[username]`; if not found, return 403.
   - Resolve the user's profile (`cache.Profiles[user.ProfileID]`).
   - Determine whether the endpoint check uses:
     - Ad-hoc requirement supplied by the handler (`AuthorizationRequirement{Capabilities: []string{"phonebook.access"}}`).
     - Or `AuthorizationRules` map for central control.
   - Evaluate capabilities: all requested permissions must be `true`. Allow combining macros (e.g., `phonebook.value` vs. `phonebook.ad_phonebook`).
   - If rule also lists allowed profile IDs, ensure the current profile matches.
   - On denial, log structured info (user, profile, endpoint, missing capability) without leaking sensitive data.
3. **Caching for Speed:** Keep per-user resolved capability sets (e.g., `map[string]bool`). Refresh this cache whenever users/profiles reload.
4. **Failure Modes:**
  - If cache is empty (e.g., startup load failed), block requests.
   - When JWT is missing, let existing auth middleware respond (avoid duplication).

## 6. Router Integration Patterns
- Provide helpers so routes stay readable:
  ```go
  func (r *gin.Engine) registerPhonebookRoutes() {
      protected := r.Group("/phonebook", middleware.InstanceJWT().MiddlewareFunc())
      protected.POST("/import", middleware.RequireCapabilities("phonebook.value"), methods.PhonebookImport)
  }
  ```
- For legacy proxy endpoints, define rule sets in a central registry:
  ```go
  var DefaultAuthorizationRules = []AuthorizationRule{
      {Path: "/phonebook", Methods: []string{"GET"}, Capabilities: []string{"phonebook.value"}},
      {Path: "/phonebook/import", Methods: []string{"POST"}, Capabilities: []string{"phonebook.ad_phonebook"}},
  }
  ```
- Add middleware that auto-selects the rule by matching `RequestURI` using the rules table when no inline requirement is provided. This keeps existing routes untouched by just inserting `middleware.RouteAuthorization()` globally.

## 7. Observability & Operations
- **Logging:** Extend `logs.Log` helpers to tag messages with `AUTHZ`. Include file version hash when reloads succeed; include validation errors.
- **Metrics:** emit counters `authz_denied_total{reason="missing_permission"}` and `authz_profile_reload_total{status="success"}` if Prometheus/StatsD is available; otherwise, stub for future use.
- **Debug Endpoint:** optional `GET /debug/authz` (admin-only) returning current profile + capability snapshot for the authenticated user to ease troubleshooting.

## 8. Testing Strategy
- **Unit Tests:**
  - Profiles parser: malformed JSON, unknown macro, duplicate IDs, mixed-case booleans.
  - Users parser: missing profile reference, reload merges.
  - Capability resolver: ensure macros propagate `value=true` implies base access.
  - Middleware decisions: table-driven tests covering allow/deny combos (advanced vs standard vs base for phonebook access).
- **Integration Tests:**
  - Spin up Gin router with JWT bypass (mock) and temp files. Touch the files to assert watcher reload updates permissions at runtime.
  - Simulate concurrent requests during reload (use `sync.WaitGroup`) to confirm no race conditions (run with `go test -race`).

## 9. Delivery Steps
1. Extend `configuration.Configuration` struct + env parsing for new paths.
2. Create `authz` package hosting loaders, watchers, and middleware helpers.
3. Wire startup (`main.go`) to initialize the authz manager before router creation and to shut it down on exit.
4. Update router setup to wrap protected endpoints with the new middleware; document examples in `README.md`.
5. Add tests + `go test ./...` guard in CI.
6. Document new env vars and debug endpoint (if implemented) in OpenAPI/README.

## 10. Risks & Mitigations
- **Large files:** use streaming decoder but keep expecting JSON size < few MB; fail if bigger with clear log.
- **Frequent writes:** debouncing ensures watchers don't thrash; consider rate limiting reload logs.
- **Partial writes (copy-on-write editors):** only swap cache after successful parse and keep last good version.
