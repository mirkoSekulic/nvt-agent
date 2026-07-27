FROM golang:1.24-bookworm AS builder

ARG TARGETOS=linux
ARG TARGETARCH

WORKDIR /src/operator
COPY operator/go.mod operator/go.sum ./
RUN go mod download
COPY operator/ ./
RUN CGO_ENABLED=0 \
    GOOS="${TARGETOS:-linux}" \
    GOARCH="${TARGETARCH:-$(go env GOARCH)}" \
    go build -trimpath -ldflags="-s -w" -o /out/nvt-execution-driver-host ./cmd/execution-driver-host

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/nvt-execution-driver-host /nvt-execution-driver-host
USER 65532:65532
ENTRYPOINT ["/nvt-execution-driver-host"]
