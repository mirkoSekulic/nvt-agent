FROM golang:1.25 AS build

WORKDIR /src
COPY protocol/resolvedrun ./protocol/resolvedrun
COPY localcontroller ./localcontroller
WORKDIR /src/localcontroller
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/nvt-local-controller ./cmd/nvt-local-controller \
  && install -d -m 0700 -o 65532 -g 65532 /out/state

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/nvt-local-controller /nvt-local-controller
COPY --from=build --chown=65532:65532 /out/state /state
USER nonroot:nonroot
EXPOSE 7480
ENTRYPOINT ["/nvt-local-controller"]
