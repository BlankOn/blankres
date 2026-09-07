# The ingest server only.
#
# The client half of this project (blankresd, the GTK window, the apt hook) reads the host's
# journal, dpkg database and saved core dumps, so a container is the wrong shape for it entirely;
# it ships as a .deb instead. What belongs in an image is the network service.

FROM rust:1-slim-bookworm AS builder

WORKDIR /src

# Copy the manifests and sources together: the workspace members reference each other by path, so
# a dependency-only pre-build layer would need every crate's manifest anyway and saves little.
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

# Only the server is built. The GTK front end is a workspace member but is never compiled here,
# so the image needs none of the GTK development libraries.
RUN cargo build --release --locked -p blankres-server \
    && strip target/release/blankres-ingest

FROM debian:bookworm-slim AS runtime

# ca-certificates for TLS to Postgres; curl for the healthcheck below.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# The service handles untrusted uploads from every machine in a fleet, so it does not run as root.
RUN useradd --system --create-home --home-dir /var/lib/blankres-ingest --shell /usr/sbin/nologin blankres

COPY --from=builder /src/target/release/blankres-ingest /usr/local/bin/blankres-ingest

# Core dumps land here. Mount a volume: an image layer is the wrong place for gigabytes of them.
VOLUME ["/var/lib/blankres-ingest"]

USER blankres
WORKDIR /var/lib/blankres-ingest

# Bind to every interface, since the point of a container is to be reached from outside it.
ENV BLANKRES_BIND=0.0.0.0:8080 \
    BLANKRES_STORAGE_ROOT=/var/lib/blankres-ingest \
    RUST_LOG=blankres_ingest=info,blankres_server=info,tower_http=info

EXPOSE 8080

# /healthz checks the database connection too, so an unreachable Postgres shows up as unhealthy
# rather than as a server that accepts requests and fails every one.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8080/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/blankres-ingest"]
