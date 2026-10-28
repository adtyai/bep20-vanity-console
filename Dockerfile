FROM golang:1.26.1-alpine@sha256:2389ebfa5b7f43eeafbd6be0c3700cc46690ef842ad962f6c5bd6be49ed82039 AS build

ENV CGO_ENABLED=0 GOWORK=off
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ENV GOOS=${TARGETOS} GOARCH=${TARGETARCH}

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -trimpath -ldflags "-s -w" -o /out/bep20-vanity-console ./cmd/bep20-vanity-console

FROM debian:bookworm-slim@sha256:f06537653ac770703bc45b4b113475bd402f451e85223f0f2837acbf89ab020a

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 65532 vanity \
    && useradd --uid 65532 --gid 65532 --no-create-home --shell /usr/sbin/nologin vanity \
    && mkdir -p /data \
    && chown vanity:vanity /data

COPY --from=build /out/bep20-vanity-console /usr/local/bin/bep20-vanity-console
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
COPY NOTICE /licenses/NOTICE
RUN chmod 755 /usr/local/bin/docker-entrypoint.sh

WORKDIR /data
ENV DATA_DIR=/data
# Start as root only to give /data to vanity, then drop privileges.
# Listen stays on 127.0.0.1. Use host networking. Do not publish ports.
# Stop grace is a runtime setting; the documented compose uses 30s.
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
