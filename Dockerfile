FROM --platform=$BUILDPLATFORM golang:1.27.3@sha256:e519d3b0a5b285e5aa53ab9eef02bc6bbb9cb04608389b743a136a9ce75f0d1e AS build
WORKDIR /src
COPY go.mod *.go LICENSE ./
ARG TARGETOS TARGETARCH VERSION=dev
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w -X main.version=$VERSION" -o /mmproxy .

FROM scratch
COPY --from=build /mmproxy /usr/local/bin/mmproxy
COPY LICENSE /LICENSE
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/mmproxy"]
