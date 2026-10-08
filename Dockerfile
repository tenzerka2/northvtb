FROM debian:bookworm-slim AS build
# Foundation supports linux/amd64. Add checked per-architecture hashes before expanding.
ARG TARGETARCH
RUN test "$TARGETARCH" = amd64 \
 && apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/* \
 && curl -fsSL https://go.dev/dl/go1.26.9.linux-amd64.tar.gz -o /tmp/go.tar.gz \
 && echo '42d158b4d8f7b61ac0a830567c940a86098fb7aac52e467a5ebec03ef5cc2f8d  /tmp/go.tar.gz' | sha256sum -c - \
 && tar -C /usr/local -xzf /tmp/go.tar.gz \
 && rm /tmp/go.tar.gz
ENV PATH=/usr/local/go/bin:$PATH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /north ./cmd/north
FROM scratch
COPY --from=build /north /north
USER 65532:65532
ENV NORTH_LISTEN_ADDR=0.0.0.0:8080
EXPOSE 8080
ENTRYPOINT ["/north"]
