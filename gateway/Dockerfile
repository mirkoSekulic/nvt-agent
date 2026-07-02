FROM golang:1.25 AS build

WORKDIR /src
COPY operator ./operator
COPY gateway ./gateway
WORKDIR /src/gateway
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/nvt-agent-gateway ./cmd/nvt-agent-gateway

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/nvt-agent-gateway /nvt-agent-gateway
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/nvt-agent-gateway"]
