# syntax=docker/dockerfile:1

# ---- build stage: syft and grype are compiled INTO the binary as Go libraries ----
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/artifactor .

# ---- runtime stage: static binary + CA certs only (no syft/grype binaries) ----
FROM alpine:3.22
RUN apk add --no-cache ca-certificates tzdata \
    && adduser -D -u 65532 -h /data scanner
USER scanner
WORKDIR /data
COPY --from=build /out/artifactor /usr/local/bin/artifactor
ENV DB_DIR=/data/db \
    PORT=8080
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/artifactor"]
