FROM golang:1.25 AS build

ARG TARGETOS=linux
ARG TARGETARCH

WORKDIR /src
COPY protocol/guestenrollment ./protocol/guestenrollment
COPY hostbundle ./hostbundle
COPY nativeegressrelay ./nativeegressrelay
WORKDIR /src/nativeegressrelay
RUN CGO_ENABLED=0 \
    GOOS="${TARGETOS:-linux}" \
    GOARCH="${TARGETARCH:-$(go env GOARCH)}" \
    go build -trimpath -ldflags="-s -w" -o /out/nvt-native-egress-relay ./cmd/nvt-native-egress-relay

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/nvt-native-egress-relay /nvt-native-egress-relay

USER 65532:65532
EXPOSE 7445 7446
ENTRYPOINT ["/nvt-native-egress-relay"]
