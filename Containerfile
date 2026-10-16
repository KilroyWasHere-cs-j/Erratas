# Build command: podman build -t erratas -f Containerfile .
# Run command:   see deploy.py (runs inside erratas-pod)

# ---- Build stage ----
FROM rust:1-bookworm AS builder

# The `tesseract` crate links against the system libtesseract/libleptonica,
# and its bindings are generated at build time, which needs libclang.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libtesseract-dev libleptonica-dev libclang-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy manifests first so a source-only change reuses the cached dependency build.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && echo "" > src/lib.rs \
    && cargo build --release \
    && rm -rf src

COPY src ./src
# Touch so cargo doesn't reuse the dummy-source build from above.
RUN touch src/main.rs src/lib.rs && cargo build --release

# ---- Run stage ----
FROM debian:bookworm-slim

# Runtime-only Tesseract libs + the English model (src/content.rs OCRs with "eng").
RUN apt-get update && apt-get install -y --no-install-recommends \
        libtesseract5 liblept5 tesseract-ocr-eng \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system appgroup \
    && useradd --system --gid appgroup --no-create-home --shell /usr/sbin/nologin appuser

WORKDIR /app

# Uploads are written to the working directory (src/server.rs), so it has to be
# writable by appuser. `rules/` is read from the working directory at runtime
# (YARA_RULESET_DIR in src/consts.rs).
COPY --from=builder --chown=appuser:appgroup /app/target/release/erratas .
COPY --chown=appuser:appgroup rules ./rules
RUN chown appuser:appgroup /app

USER appuser

EXPOSE 9000

# Hosted mode: `erratas host <host> <port>`. Bind 0.0.0.0 so the pod's
# published port can reach it.
ENTRYPOINT ["./erratas", "host", "0.0.0.0", "9000"]
