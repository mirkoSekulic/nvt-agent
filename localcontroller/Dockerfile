FROM golang:1.25 AS build

WORKDIR /src
COPY protocol/resolvedrun ./protocol/resolvedrun
COPY localcontroller ./localcontroller
WORKDIR /src/localcontroller
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/nvt-local-controller ./cmd/nvt-local-controller

FROM docker:27-cli
COPY --from=build /out/nvt-local-controller /nvt-local-controller
RUN install -d -m 0700 /state
USER root
EXPOSE 7480
ENTRYPOINT ["/nvt-local-controller"]
