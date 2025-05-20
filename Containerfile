# Use Go as base image for building
FROM docker.io/library/golang:1.24

# Set working directory
WORKDIR /app

# Copy source code
COPY . .

# Download dependencies
RUN go mod download

# Build the Go application
RUN go build -o whale

# Expose the service port (based on your configuration)
EXPOSE 8080

# Run the binary (fix the command format)
CMD ["./whale"]