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
| `NETHVOICE_MIDDLEWARE_FREEPBX_APIS` | Comma-separated list of FreePBX APIs that bypass JWT | See default APIs in code |
| `NETHVOICE_MIDDLEWARE_MARIADB_HOST` | MariaDB server hostname | `localhost` |
| `NETHVOICE_MIDDLEWARE_MARIADB_PORT` | MariaDB server port | **Required** |
| `NETHVOICE_MIDDLEWARE_MARIADB_USER` | MariaDB username | `root` |
| `NETHVOICE_MIDDLEWARE_MARIADB_PASSWORD` | MariaDB password | **Required** |
| `NETHVOICE_MIDDLEWARE_MARIADB_DATABASE` | MariaDB database name | `nethcti3` |
| `NETHVOICE_MIDDLEWARE_TRUSTED_PROXY` | Trusted proxy IP or CIDR for Gin's [trusted proxies](https://gin-gonic.com/en/docs/deployment/#dont-trust-all-proxies) | `127.0.0.1` |
| `NETHVOICE_MATRIX_BASE_URL` | Base URL of the Matrix homeserver for chat integration | _(empty)_ |

## Testing

### Prerequisites

- Go 1.26 or later
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

## Container Management

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

Before running the middleware, ensure MariaDB is available and configured:

```bash
podman run -d --name mariadb-nethcti \
  --env MARIADB_ROOT_PASSWORD=your-secure-password \
  --env MARIADB_DATABASE=nethcti_middleware \
  -p 3306:3306 \
  mariadb:latest
```

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
  --env NETHVOICE_MIDDLEWARE_MARIADB_HOST=mariadb \
  --env NETHVOICE_MIDDLEWARE_MARIADB_PORT=3306 \
  --env NETHVOICE_MIDDLEWARE_MARIADB_USER=root \
  --env NETHVOICE_MIDDLEWARE_MARIADB_PASSWORD=your-secure-password \
  --volume ./data:/var/log/nethcti \
  --replace nethcti-middleware
