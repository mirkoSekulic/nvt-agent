FROM golang:1.24-bookworm AS builder

WORKDIR /src
COPY tests/fixtures/echo/go.mod ./
COPY tests/fixtures/echo/main.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/echo .

FROM scratch
COPY --from=builder /out/echo /echo
EXPOSE 8080
ENTRYPOINT ["/echo"]
