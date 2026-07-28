# syntax=docker/dockerfile:1

FROM golang:1.24-alpine@sha256:8bee1901f1e530bfb4a7850aa7a479d17ae3a18beb6e09064ed54cfd245b7191 AS builder
ARG TARGETARCH
ARG NVT_VERSION
ARG NVT_REVISION
WORKDIR /src
RUN apk add --no-cache bash openssl
COPY hostbundle/ hostbundle/
COPY runtime/agentd/ runtime/agentd/
COPY tests/fixtures/host-bundle-registry/main.go tests/fixtures/host-bundle-registry/main.go
RUN NVT_HOST_BUNDLE_ARCH=amd64 /src/hostbundle/build.sh "${NVT_VERSION}" "${NVT_REVISION}" /fixture && \
    cd /src && CGO_ENABLED=0 GOOS=linux GOARCH="${TARGETARCH}" \
      go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' \
      -o /fixture/nvt-host-bundle-registry ./tests/fixtures/host-bundle-registry/main.go && \
    openssl req -x509 -newkey rsa:2048 -nodes -days 2 -sha256 \
      -subj /CN=nvt-host-bundle-registry.nvt.svc.cluster.local \
      -addext subjectAltName=DNS:nvt-host-bundle-registry.nvt.svc,DNS:nvt-host-bundle-registry.nvt.svc.cluster.local \
      -keyout /fixture/tls.key -out /fixture/tls.crt >/dev/null 2>&1 && \
    chmod 0755 /fixture/nvt-host-bundle-registry && chmod 0600 /fixture/tls.key && chmod 0644 /fixture/tls.crt

FROM alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce
COPY --from=builder /fixture /fixture
EXPOSE 443
ENTRYPOINT ["/fixture/nvt-host-bundle-registry"]
