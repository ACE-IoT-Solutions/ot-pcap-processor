FROM docker.io/library/rust:1.98-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock README.md LICENSE ./
COPY src ./src
RUN cargo build --release --locked

FROM docker.io/library/debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tcpdump \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/ot-pcap-processor /usr/local/bin/ot-pcap-processor
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/ot-pcap-processor"]
