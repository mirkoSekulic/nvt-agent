FROM golang:1.25 AS build

WORKDIR /src
COPY operator ./operator
COPY producers/github-comments ./producers/github-comments
WORKDIR /src/producers/github-comments
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/github-comments ./cmd/github-comments

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/github-comments /github-comments
USER nonroot:nonroot
ENTRYPOINT ["/github-comments"]
