# Stage 1: Build the static binary
FROM golang:1.24-alpine AS builder
WORKDIR /app
ENV CGO_ENABLED=0
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .

RUN --mount=type=cache,target=/root/.cache/go-build go build -ldflags="-s -w \
    -X minecharts/cmd/version.Version=${VERSION} \
    -X minecharts/cmd/version.Commit=${COMMIT} \
    -X minecharts/cmd/version.BuildDate=${BUILD_DATE}" \
    -o build/minecharts-api .

# Stage 2: Create the minimal image using scratch
FROM alpine:latest
WORKDIR /app

RUN mkdir -p /app/data && chmod 777 /app/data

COPY --from=builder /app/build/minecharts-api .

EXPOSE 8080
ENTRYPOINT ["./minecharts-api"]
