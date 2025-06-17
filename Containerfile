# Use Go as base image for building
FROM docker.io/golang:1.24-alpine3.22 AS builder

# Set working directory
WORKDIR /app

# Copy source code
COPY . .

# Download dependencies
RUN go mod download

# Build the Go application
RUN go build -o whale

FROM docker.io/alpine:3.22 AS runtime

# Set working directory
WORKDIR /app

# Install oath-toolkit-oathtool in the runtime image
RUN apk --no-cache add oath-toolkit-oathtool

# Copy the built binary from the builder stage
COPY --from=builder /app/whale .

# Expose the service port (based on your configuration)
EXPOSE 8080

# Run the binary (fix the command format)
CMD ["./whale"]
