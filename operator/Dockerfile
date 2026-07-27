FROM golang:1.24-bookworm AS builder

ARG TARGETOS=linux
ARG TARGETARCH

WORKDIR /src

COPY protocol/guestenrollment/go.mod protocol/guestenrollment/go.mod
COPY operator/go.mod operator/go.sum operator/
WORKDIR /src/operator
RUN go mod download

COPY protocol/guestenrollment/ ../protocol/guestenrollment/
COPY operator/ ./
RUN CGO_ENABLED=0 \
    GOOS="${TARGETOS:-linux}" \
    GOARCH="${TARGETARCH:-$(go env GOARCH)}" \
    go build -trimpath -ldflags="-s -w" -o /out/manager ./cmd/manager

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /out/manager /manager

USER 65532:65532
EXPOSE 8080 8081 8082
ENTRYPOINT ["/manager"]
