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
COPY NOTICE /licenses/NOTICE

USER vanity
WORKDIR /data
ENV DATA_DIR=/data
ENTRYPOINT ["/usr/local/bin/bep20-vanity-console"]
