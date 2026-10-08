FROM golang:1.26.9-bookworm AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /north ./cmd/north
FROM scratch
COPY --from=build /north /north
USER 65532:65532
ENV NORTH_LISTEN_ADDR=0.0.0.0:8080
EXPOSE 8080
ENTRYPOINT ["/north"]
