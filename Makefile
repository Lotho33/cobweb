# Build/test wrappers that work from BOTH places:
#
#   * inside the devcontainer (or any shell with `cargo` on PATH) → runs cargo directly
#   * on the bare host (Aurora/Kinoite has no cargo)              → runs inside
#     rust:1-bookworm via podman, reusing named cache volumes
#
#   make test | check | fmt | run | shell
#
# Default features (flaresolverr) are on. `ytdlp` is opt-in:
#   cargo test --features ytdlp

HAVE_CARGO := $(shell command -v cargo >/dev/null 2>&1 && echo yes)

IMAGE      ?= docker.io/library/rust:1-bookworm
CARGO_VOL  ?= cobweb-cargo-registry
TARGET_VOL ?= cobweb-target
PODMAN      = podman run --rm -it -v "$(CURDIR)":/w:z -w /w \
              -v $(CARGO_VOL):/usr/local/cargo/registry -v $(TARGET_VOL):/w/target \
              -e CC=clang -e CXX=clang++ -e CARGO_TERM_COLOR=always
# wreq's BoringSSL (btls) needs cmake+clang; chromium for the browser tests.
PREP        = apt-get update -qq && apt-get install -y -qq cmake clang chromium fonts-liberation >/dev/null 2>&1; \
              rustup component add clippy rustfmt >/dev/null 2>&1 || true;

# $(call cargo,<cargo command>[,<extra podman args>])
ifeq ($(HAVE_CARGO),yes)
cargo = bash -c '$(1)'
else
cargo = $(PODMAN) $(2) $(IMAGE) bash -c '$(PREP) $(1)'
endif

.PHONY: test check fmt run shell build-image
test:
	$(call cargo,cargo test)

check:
	$(call cargo,cargo clippy --all-targets -- -D warnings)

fmt:
	$(call cargo,cargo fmt)

run:
	$(call cargo,cargo run -- --config config.dev.toml,-p 8191:8191)

shell:
	$(call cargo,exec bash,-p 8191:8191)

build-image:
	podman build -t cobweb:latest .
