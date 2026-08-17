FROM golang:1.25 AS build
WORKDIR /src
COPY producer/testfixture/main.go ./main.go
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/external-producer-fixture ./main.go

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/external-producer-fixture /external-producer-fixture
USER nonroot:nonroot
ENTRYPOINT ["/external-producer-fixture"]
