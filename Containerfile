ARG RUST_IMAGE=docker.io/library/rust:1.95.0-bookworm
ARG RUNTIME_IMAGE=docker.io/library/debian:bookworm-slim

FROM ${RUST_IMAGE} AS builder
WORKDIR /usr/src/fluxheim

RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY src ./src

ARG FLUXHEIM_FEATURES=default
RUN if [ "${FLUXHEIM_FEATURES}" = "default" ]; then \
        cargo build --locked --release; \
    else \
        cargo build --locked --release --no-default-features --features "${FLUXHEIM_FEATURES}"; \
    fi

FROM ${RUNTIME_IMAGE}

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /etc/fluxheim /var/lib/fluxheim/acme /var/cache/fluxheim /srv/fluxheim \
    && chown -R 65532:65532 /etc/fluxheim /var/lib/fluxheim /var/cache/fluxheim /srv/fluxheim

COPY --from=builder /usr/src/fluxheim/target/release/fluxheim /usr/local/bin/fluxheim
COPY examples/fluxheim.toml /etc/fluxheim/fluxheim.toml

USER 65532:65532
EXPOSE 8080 8443

ENTRYPOINT ["/usr/local/bin/fluxheim"]
CMD ["--config", "/etc/fluxheim/fluxheim.toml"]
