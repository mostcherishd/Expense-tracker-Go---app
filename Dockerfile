# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /expressappdir

# Copy go.mod first
COPY go.mod ./.
# RUN go mod download
RUN go mod download
# Copy all source files
COPY . .

# Build the binary
RUN go build -o devscale_expense . 

# Run stage
FROM alpine:latest

# Security: Run as non-root
RUN addgroup -S express && adduser -S express -G express



WORKDIR /expressappdir

COPY --from=builder /expressappdir/devscale_expense .

ENV PORT=8080
EXPOSE 8080

USER express
CMD ["./devscale_expense"]