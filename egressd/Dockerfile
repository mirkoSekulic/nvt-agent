# Build the egressd credential-injecting egress proxy.
FROM golang:1.25 AS build
WORKDIR /src
COPY egressd/go.mod ./
RUN go mod download
COPY egressd/ ./
RUN CGO_ENABLED=0 go build -o /out/egressd ./cmd/egressd

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/egressd /usr/local/bin/egressd
ENTRYPOINT ["/usr/local/bin/egressd"]
