# Use Go as base image for building
FROM docker.io/golang:1.24

# Install oath-toolkit-oathtool
RUN apt-get update && apt-get install -y oathtool && rm -rf /var/lib/apt/lists/*

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
