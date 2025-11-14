# AGENTS.md

This document provides instructions for AI coding agents to interact with the `nethcti-middleware` codebase.

## About the Project

This project is a middleware service written in Go. It provides a RESTful API and is containerized using Podman.
Designed to run inside NethServer 8.

## Development Environment

The development environment is based on Go and Podman.
1.  **Prerequisites**:
    *   Go (version 1.24 or later)
    *   Podman
    *   `oath-toolkit-oathtool`

2.  **Setup**:
    *   Clone the repository.
    *   Install Go dependencies:
        ```bash
        go mod download
        ```

3.  **Building**:
    *   To build the application binary:
        ```bash
        go build -o whale
        ```
    *   To build the Docker container image:
        ```bash
        podman build -t nethcti-middleware .
        ```

4. **Testing**
    * ALWAYS start mariadb container before starting tests
        ```bash
         podman run -d --rm --name mariadb-test -e MYSQL_ROOT_PASSWORD=root -e MYSQL_DATABASE=nethcti3 \
         -p 3306:3306 docker.io/library/mariadb:10.8.2
        ```
    * Run tests, but make sure that mariadb-test container is running
        ```bash
        go test -v -cover ./...
        ```
    * Generate coverage report
        ```bash
        go test -coverprofile=coverage.out ./...
        go tool cover -html=coverage.out -o coverage.html
        ```
    * Stop the test mariadb container
        ```bash
        podman stop mariadb-test
        ```

## Testing Instructions

The project includes a dedicated test suite covering its core functionality.

*   When adding new features or fixing bugs, you **must** also add corresponding tests.
*   Use Go's standard testing library.
*   Place test files alongside the source files using the `_test.go` suffix (e.g., `feature_test.go`).
*   Run tests using the following command:
    ```bash
    go test ./...
    ```

## Definition of Done

A task or feature is considered "done" when it meets all the following criteria:

1.  **Code is complete**: The feature is fully implemented according to the requirements.
2.  **Builds successfully**: The `go build` command completes without errors.
3.  **Tests are included**: New, relevant unit tests have been added to cover the new code.
4.  **All tests pass**: The `go test ./...` command runs successfully with no failing tests.
5.  **Linting is clean**: The code adheres to standard Go formatting and linting rules. Run `go fmt ./...` before committing.
6.  **Documentation is updated**: Any relevant documentation, including the OpenAPI spec  `doc/openapi.yaml`, has been updated.
