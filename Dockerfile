# Multi-stage build.
#
#   docker build -t cobweb:latest .                        # vnc + flaresolverr
#   docker build --build-arg FEATURES="flaresolverr" \
#                -t cobweb:lean .                           # fast-path + FS only
#   docker build --build-arg FEATURES="vnc,flaresolverr,ytdlp" \
#                --build-arg WITH_YTDLP=1 -t cobweb:ytdlp . # + yt-dlp binary
#
# yt-dlp is opt-in on purpose: it's a fast-moving, heavyweight external binary.
# The default image does NOT carry it.

# ---- build ----
FROM rust:1-bookworm AS build
WORKDIR /src
# wreq's TLS backend (btls / BoringSSL) compiles from source.
RUN apt-get update && apt-get install -y --no-install-recommends cmake clang \
 && rm -rf /var/lib/apt/lists/*
ENV CC=clang CXX=clang++

# Cache deps against Cargo.toml/lock before copying sources.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs && echo '' > src/lib.rs \
 && cargo build --release --locked --no-default-features 2>/dev/null || true
COPY . .

ARG FEATURES="vnc,flaresolverr"
RUN touch src/main.rs src/lib.rs \
 && cargo build --release --locked --no-default-features --features "$FEATURES" \
 && strip target/release/cobweb

# ---- runtime ----
FROM debian:bookworm-slim
ARG WITH_YTDLP=0
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates tini wget \
      chromium fonts-liberation xvfb x11vnc \
 && if [ "$WITH_YTDLP" = "1" ]; then \
      apt-get install -y --no-install-recommends yt-dlp || \
      (apt-get install -y --no-install-recommends python3-pip && pip3 install --no-cache-dir --break-system-packages yt-dlp); \
    fi \
 && rm -rf /var/lib/apt/lists/* /usr/share/doc/* /usr/share/man/* /usr/share/locale/*

COPY --from=build /src/target/release/cobweb /usr/local/bin/cobweb
COPY --from=build /src/vendor/novnc /opt/novnc
RUN useradd -m -u 10001 cobweb && mkdir -p /data && chown cobweb /data
USER cobweb

ENV COBWEB_CONFIG=/config/config.toml
EXPOSE 8191
ENTRYPOINT ["tini", "--", "cobweb"]
