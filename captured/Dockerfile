FROM golang:1.25 AS build
WORKDIR /src
COPY captured/go.mod ./
COPY captured/ ./
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/captured ./cmd/captured

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/captured /usr/local/bin/captured
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/captured"]
