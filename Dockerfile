FROM --platform=$BUILDPLATFORM golang:1.27.4@sha256:5f1b98fa02fe396ebce2a0227a0e08309e11792915b9dd2e1f71053d7e7e6666 AS build
WORKDIR /src
COPY go.mod *.go LICENSE LICENSE-Go ./
ARG TARGETOS TARGETARCH VERSION=dev
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w -X main.version=$VERSION" -o /mmproxy .

FROM scratch
LABEL org.opencontainers.image.source="https://github.com/zekihan/mmproxy" \
      org.opencontainers.image.title="mmproxy" \
      org.opencontainers.image.description="Event-driven Linux PROXY protocol relay" \
      org.opencontainers.image.licenses="AGPL-3.0-only"
COPY --from=build /mmproxy /usr/local/bin/mmproxy
COPY LICENSE /LICENSE
COPY LICENSE-Go /LICENSE-Go
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/mmproxy"]
