# syntax=docker/dockerfile:1

FROM golang:1.24-alpine@sha256:8bee1901f1e530bfb4a7850aa7a479d17ae3a18beb6e09064ed54cfd245b7191 AS builder

ARG TARGETOS=linux
ARG TARGETARCH
WORKDIR /src
COPY protocol/guestenrollment/go.mod protocol/guestenrollment/go.mod
COPY protocol/resolvedrun/go.mod protocol/resolvedrun/go.mod
COPY operator/go.mod operator/go.sum operator/
COPY executiondrivers/azure/go.mod executiondrivers/azure/go.sum executiondrivers/azure/
COPY hostbundle/go.mod hostbundle/go.mod
RUN cd /src/executiondrivers/azure && go mod download
COPY protocol/guestenrollment/ protocol/guestenrollment/
COPY protocol/resolvedrun/ protocol/resolvedrun/
COPY operator/executiondriver/ operator/executiondriver/
COPY executiondrivers/azure/ executiondrivers/azure/
COPY hostbundle/ hostbundle/
RUN cd /src/executiondrivers/azure && CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
      go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o /out/nvt-azure-driver ./cmd/nvt-azure-driver && \
    cd /src/hostbundle && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
      go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o /out/nvt-host-bootstrap ./cmd/nvt-host-bootstrap

FROM gcr.io/distroless/static-debian12:nonroot@sha256:f5b485ea962d9bd1186b2f6b3a061191539b905b82ec395de78cbfae51f20e35
COPY --from=builder /out/nvt-azure-driver /usr/local/bin/nvt-azure-driver
COPY --from=builder /out/nvt-host-bootstrap /opt/nvt-azure/nvt-host-bootstrap
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/nvt-azure-driver"]
