# nethcti-middleware

## Configuration

The application can be configured using the following environment variables:

| Variable | Description | Default Value |
|----------|-------------|---------------|
| `NETHVOICE_MIDDLEWARE_LISTEN_ADDRESS` | Address and port where the middleware will listen | `127.0.0.1:8080` |
| `NETHVOICE_MIDDLEWARE_V1_PROTOCOL` | Protocol used for V1 API connections | `https` |
| `NETHVOICE_MIDDLEWARE_V1_API_ENDPOINT` | Hostname/IP for V1 API endpoint | **Required** |
| `NETHVOICE_MIDDLEWARE_V1_WS_ENDPOINT` | Hostname/IP for V1 WebSocket endpoint | **Required** |
| `NETHVOICE_MIDDLEWARE_V1_API_PATH` | Path prefix for V1 API calls | _(empty)_ |
| `NETHVOICE_MIDDLEWARE_V1_WS_PATH` | Path for V1 WebSocket connections | `/socket.io` |
| `NETHVOICE_MIDDLEWARE_SENSITIVE_LIST` | Comma-separated list of sensitive field names for logging | `password,secret,token,passphrase,private,key` |
| `NETHVOICE_MIDDLEWARE_SECRETS_DIR` | Directory path for storing secrets | `/var/lib/whale/secrets` |
| `NETHVOICE_MIDDLEWARE_ISSUER_2FA` | Issuer name for 2FA tokens | `NethVoice` |
| `NETHVOICE_MIDDLEWARE_SUPER_ADMIN_TOKEN` | Bearer token for super admin API endpoints (e.g., `/admin/reload`) | `CHANGEME` |
| `NETHVOICE_MIDDLEWARE_SUPER_ADMIN_ALLOW_IPS` | Comma-separated list of allowed IPs/CIDR ranges for super admin access | `127.0.0.0/8` |
| `NETHVOICE_MIDDLEWARE_FREEPBX_APIS` | Comma-separated list of FreePBX APIs that bypass JWT | See default APIs in code |
| `PHONEBOOK_MARIADB_HOST` | MariaDB server hostname | `localhost` |
| `PHONEBOOK_MARIADB_PORT` | MariaDB server port | **Required** |
| `PHONEBOOK_MARIADB_USER` | MariaDB username | `root` |
| `PHONEBOOK_MARIADB_PASSWORD` | MariaDB password | **Required** |
| `PHONEBOOK_MARIADB_DB` | MariaDB database name | `nethcti3` |

## Testing

### Prerequisites

- Go 1.24 or later
- `oathtool` package (for 2FA testing)
- MariaDB 10.5+ or MySQL 8.0+ (for phonebook and persistence features)

Install oathtool on Ubuntu/Debian:
```bash
sudo apt-get install oathtool
```

### Running Tests

Run all tests:
```bash
go test ./...
```

Run tests with verbose output:
```bash
go test -v ./...
```

### Test Environment

Tests automatically create a temporary test environment with:
- Mock NetCTI server for authentication testing
- Temporary secrets directory (`/tmp/test-secrets`)
- Test JWT secret key
- Clean state for each test

The test suite covers:
- Authentication and login flows
- 2FA setup, verification, and management
- JWT token handling
- Recovery codes functionality
- Error handling and edge cases

## Token Management and Profile Reload

### User Token Refresh

- The middleware provides a `/refresh` endpoint for authenticated users to obtain a new JWT token with current profile capabilities
- To update user capabilities, update the `profiles.json` and/or `users.json` files, then send the SIGUSR1 signal or call the `/admin/reload` endpoint using super admin token

Example with SIGUSR1:
```bash
# Update configuration files
sudo nano /etc/nethcti/profiles.json

# Reload profiles into memory
kill -USR1 $(pgrep -f nethcti-middleware)

# Users receive WebSocket notification and can call /refresh to get new tokens
```

See `middleware/README.md` for detailed profile configuration and reload documentation.

### WebSocket Global Profile Reload Event

When the admin reloads profiles via `SIGUSR1` or `/admin/reload` endpoint, the server broadcasts a global WebSocket notification to all connected clients. This tells clients profiles have been reloaded and they may refresh tokens.

Example socket.io message (server -> clients):
```
42["profile_reload_global", {"trigger": "signal"}]
```

- `profile_reload_global`: event name
- payload: JSON object with `trigger` property (value: `signal` for SIGUSR1 or `api` for `/admin/reload` endpoint)

Clients should listen for this event and optionally call the `/refresh` endpoint to obtain an updated JWT with the refreshed capabilities.

## Super Admin Profile Reload via API

The `/admin/reload` endpoint allows super administrators to reload all profiles and users from configuration files remotely.

### Security

The `/admin/reload` endpoint is protected by two layers of security:

1. **IP Whitelist**: Only requests from whitelisted IP addresses/CIDR ranges are accepted
2. **Bearer Token Authentication**: Additionally requires a valid super admin bearer token

### Configuration

**IP Whitelist** (`NETHVOICE_MIDDLEWARE_SUPER_ADMIN_ALLOW_IPS`):
- Default: `127.0.0.0/8` (localhost only - secure default)
- Supports single IPs: `192.168.1.100`
- Supports CIDR ranges: `10.0.0.0/8,192.168.0.0/16`
- Multiple values: comma-separated without spaces

Example:
```bash
export NETHVOICE_MIDDLEWARE_SUPER_ADMIN_ALLOW_IPS="127.0.0.1,10.0.0.0/8,192.168.1.0/24"
```

**Bearer Token** (`NETHVOICE_MIDDLEWARE_SUPER_ADMIN_TOKEN`):
- Default: `CHANGEME` (must be changed in production)
- Used in Authorization header: `Bearer <token>`

### Usage Examples

**From localhost (default allowed):**
```bash
curl -X POST http://localhost:8080/admin/reload \
  -H "Authorization: Bearer CHANGEME"
```

**From remote IP (must be whitelisted):**
```bash
# First, whitelist the IP:
export NETHVOICE_MIDDLEWARE_SUPER_ADMIN_ALLOW_IPS="127.0.0.1,192.168.100.50"

# Then make the request from 192.168.100.50:
curl -X POST http://localhost:8080/admin/reload \
  -H "Authorization: Bearer your-secure-token"
```

### Response

**Success (200 OK):**
```json
{
  "code": 200,
  "message": "profiles reloaded successfully",
  "data": {
    "trigger": "api"
  }
}
```

**IP Not Whitelisted (403 Forbidden):**
```json
{
  "code": 403,
  "message": "access denied: IP not in allowed list",
  "data": null
}
```

**Invalid Token (401 Unauthorized):**
```json
{
  "code": 401,
  "message": "super admin authentication required",
  "data": null
}
```

### Workflow

1. Administrator updates `profiles.json` and/or `users.json`
2. Administrator calls `/admin/reload` endpoint with valid token from whitelisted IP
3. Middleware reloads configuration into memory
4. All connected WebSocket clients receive `profile_reload_global` event
5. Clients call `/refresh` to obtain new JWT tokens with updated capabilities
6. Users can now use new capabilities immediately

## Container Management

### MariaDB Setup

Before running the middleware, ensure MariaDB is available and configured:

**Option 1: MariaDB Container**

```bash
podman run -d --name mariadb \
  --env MARIADB_ROOT_PASSWORD=your-secure-password \
  --env MARIADB_DATABASE=nethcti_middleware \
  -p 3306:3306 \
  mariadb:latest
```

**Option 2: MariaDB on Host**

Ensure MariaDB service is running:
```bash
systemctl start mariadb
# or for Docker/system MariaDB container
```

### Stop and Clean Up

Stop the existing container and clean up system resources:

```bash
podman stop nethcti-container
podman system prune --all --volumes --force
```

### Build Image

Build the Docker image:

```bash
podman build -t nethcti-middleware .
```

### Run Container

Run the container with environment configuration:

```bash
podman run -d -p 8080:8080 --name nethcti-container \
  --env NETHVOICE_MIDDLEWARE_LISTEN_ADDRESS=:8080 \
  --env NETHVOICE_MIDDLEWARE_V1_PROTOCOL=https \
  --env NETHVOICE_MIDDLEWARE_V1_API_ENDPOINT=your-api-endpoint.example.com \
  --env NETHVOICE_MIDDLEWARE_V1_WS_ENDPOINT=your-ws-endpoint.example.com \
  --env NETHVOICE_MIDDLEWARE_V1_API_PATH=/webrest \
  --env NETHVOICE_MIDDLEWARE_V1_WS_PATH=/socket.io \
  --env NETHVOICE_MIDDLEWARE_SECRETS_DIR=/var/log/nethcti \
  --env PHONEBOOK_MARIADB_HOST=mariadb \
  --env PHONEBOOK_MARIADB_PORT=3306 \
  --env PHONEBOOK_MARIADB_USER=root \
  --env PHONEBOOK_MARIADB_PASSWORD=your-secure-password \
  --volume ./data:/var/log/nethcti \
  --replace nethcti-middleware

### Connection Pool Configuration

The middleware uses a connection pool with the following defaults:
- Max open connections: 25
- Max idle connections: 5
- Connection max lifetime: 5 minutes

These can be adjusted in `db/db.go` if needed for your workload.
