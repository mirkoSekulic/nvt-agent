FROM golang:1.25 AS build

WORKDIR /src
COPY credentialportal ./credentialportal
WORKDIR /src/credentialportal
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/nvt-credential-portal ./cmd/nvt-credential-portal

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/nvt-credential-portal /nvt-credential-portal
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/nvt-credential-portal"]
