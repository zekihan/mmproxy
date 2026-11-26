FROM --platform=$BUILDPLATFORM golang:1.27.3@sha256:e519d3b0a5b285e5aa53ab9eef02bc6bbb9cb04608389b743a136a9ce75f0d1e AS build
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
