# nethcti-middleware

## Configuration

The application can be configured using the following environment variables:

| Variable | Description | Default Value |
|----------|-------------|---------------|
| `NETHVOICE_MIDDLEWARE_LISTEN_ADDRESS` | Address and port where the middleware will listen | `127.0.0.1:8080` |
| `NETHVOICE_MIDDLEWARE_SECRET_JWT` | Secret key used for JWT token signing and validation | Auto-generated UUID |
| `NETHVOICE_MIDDLEWARE_V1_PROTOCOL` | Protocol used for V1 API connections | `https` |
| `NETHVOICE_MIDDLEWARE_V1_API_ENDPOINT` | Hostname/IP for V1 API endpoint | `cti2.demo-heron.sf.nethserver.net` |
| `NETHVOICE_MIDDLEWARE_V1_WS_ENDPOINT` | Hostname/IP for V1 WebSocket endpoint | `cti2.demo-heron.sf.nethserver.net` |
| `NETHVOICE_MIDDLEWARE_V1_API_PATH` | Path prefix for V1 API calls | _(empty)_ |
| `NETHVOICE_MIDDLEWARE_V1_WS_PATH` | Path for V1 WebSocket connections | `/socket.io` |
| `NETHVOICE_MIDDLEWARE_SENSITIVE_LIST` | Comma-separated list of sensitive field names for logging | `password,secret,token,passphrase,private,key` |
| `NETHVOICE_MIDDLEWARE_SECRETS_DIR` | Directory path for storing secrets | **Required** |
| `ISSUER_2FA` | Issuer name for 2FA tokens | `NethVoice` |

## Testing

### Prerequisites

- Go 1.24 or later
- `oathtool` package (for 2FA testing)

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

Run the container with environment configuration:

```bash
podman run -d -p 8080:8080 --name nethcti-container \
  --env NETHVOICE_MIDDLEWARE_LISTEN_ADDRESS=:8080 \
  --env NETHVOICE_MIDDLEWARE_SECRET_JWT=test \
  --env NETHVOICE_MIDDLEWARE_SECRETS_DIR=/var/log \
  --env NETHVOICE_MIDDLEWARE_V1_API_PATH=/webrest \
  --replace nethcti-middleware
```
