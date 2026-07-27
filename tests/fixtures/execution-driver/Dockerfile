FROM golang:1.24-bookworm AS builder

WORKDIR /src/operator
COPY operator/go.mod operator/go.sum ./
RUN go mod download
COPY operator/executiondriver/ ./executiondriver/
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/fake-driver ./executiondriver/testdata/fake-driver

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/fake-driver /fake-driver
USER 65532:65532
ENTRYPOINT ["/fake-driver"]
