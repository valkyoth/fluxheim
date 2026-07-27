ARG RUST_IMAGE=docker.io/library/rust:1.97.1-bookworm@sha256:77fac8b98f9f46062bb680b6d25d5bcaabfc400143952ebc572e924bcbedc3fa
ARG RUNTIME_IMAGE=docker.io/library/debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818
ARG FLUXHEIM_CONFIG=packaging/container/fluxheim.toml

FROM ${RUST_IMAGE} AS builder
WORKDIR /usr/src/fluxheim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p scripts

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY build.rs ./
COPY vendor ./vendor
COPY packaging/systemd ./packaging/systemd
COPY crates ./crates
COPY src ./src
COPY scripts/validate-features.sh scripts/feature-policy.sh ./scripts/

ARG FLUXHEIM_FEATURES=profile-full,acme-client,metrics,metrics-otlp,otel-tracing,otel-otlp
RUN if [ "${FLUXHEIM_FEATURES}" = "default" ]; then \
        cargo build --locked --release; \
    else \
        scripts/validate-features.sh "${FLUXHEIM_FEATURES}" && \
        cargo build --locked --release --no-default-features --features "${FLUXHEIM_FEATURES}"; \
    fi

FROM ${RUNTIME_IMAGE}
ARG FLUXHEIM_CONFIG=packaging/container/fluxheim.toml
ARG FLUXHEIM_RUNTIME_UID=65532
ARG FLUXHEIM_RUNTIME_GID=65532

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /etc/fluxheim /run/fluxheim /var/lib/fluxheim/acme /var/cache/fluxheim /var/log/fluxheim /srv/fluxheim \
    && chown -R ${FLUXHEIM_RUNTIME_UID}:${FLUXHEIM_RUNTIME_GID} /etc/fluxheim /run/fluxheim /var/lib/fluxheim /var/cache/fluxheim /var/log/fluxheim /srv/fluxheim

COPY --from=builder /usr/src/fluxheim/target/release/fluxheim /usr/local/bin/fluxheim
COPY --from=builder /usr/src/fluxheim/target/release/fluxheim-acme /usr/local/bin/fluxheim-acme
COPY ${FLUXHEIM_CONFIG} /etc/fluxheim/fluxheim.toml
COPY packaging/default/index.html /srv/fluxheim/index.html

USER ${FLUXHEIM_RUNTIME_UID}:${FLUXHEIM_RUNTIME_GID}
EXPOSE 8080 8443

ENTRYPOINT ["/usr/local/bin/fluxheim"]
CMD ["--config", "/etc/fluxheim/fluxheim.toml"]
