# Build stage
# 1. Upgrade the builder container to Go 1.25 (or latest alpine equivalent)
# FROM golang:1.25-alpine AS builder
# WORKDIR /app
# COPY go.mod go.sum ./
# RUN go mod download
# COPY *.go ./
# RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o chaincode .

# # Production execution stage
# FROM alpine:latest
# RUN apk add --no-cache tzdata
# WORKDIR /app
# COPY --from=builder /app/chaincode .
# EXPOSE 7052
# CMD ["./chaincode"]

# Build stage
FROM golang:1.25-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o chaincode .

# Production execution stage
FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/chaincode .
EXPOSE 9990
CMD ["./chaincode"]