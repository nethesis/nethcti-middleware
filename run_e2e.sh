#!/bin/bash

set -e

go build main.go

# Set environment variables and run the middleware
NETHVOICE_MIDDLEWARE_LISTEN_ADDRESS=127.0.0.1:8080 \
NETHVOICE_MIDDLEWARE_V1_API_ENDPOINT=your-api-endpoint.example.com \
NETHVOICE_MIDDLEWARE_V1_WS_ENDPOINT=your-ws-endpoint.example.com \
RTP_PROXY_ADDR=127.0.0.1 \
RTP_PROXY_PORT=5004 \
JITTER_BUFFER=on \
PLAYBACK_RATE=20 \
./main &

# run the publisher
go run e2e/intercome.go 