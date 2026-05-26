FROM rust:1-bookworm

RUN apt-get update     && apt-get install -y --no-install-recommends pkg-config ca-certificates python3 python3-pip     && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
COPY . /workspace
RUN cargo test --no-run

CMD ["cargo", "test"]
