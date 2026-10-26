# syntax=docker/dockerfile:1

# Runtime image only: GoReleaser builds the static binary for each target
# architecture and stages it as ./artifactor in the Docker build context
# (see .goreleaser.yaml).
FROM alpine:3.24
RUN apk add --no-cache ca-certificates tzdata \
    && adduser -D -u 65532 -h /data scanner
USER scanner
WORKDIR /data
COPY artifactor /usr/local/bin/artifactor
ENV DB_DIR=/data/db \
    PORT=8080
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/artifactor"]
