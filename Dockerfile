# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o copa-wiz ./cmd/copa-wiz

# Final stage
FROM alpine:3.19

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/copa-wiz .

# Create a non-root user
RUN adduser -D -g '' appuser
USER appuser

ENTRYPOINT ["/app/copa-wiz"] 