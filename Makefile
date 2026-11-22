# Build/test wrappers that work from BOTH places:
#
#   * inside the devcontainer (or any shell with `cargo` on PATH) → runs cargo directly
#   * on the bare host (Aurora/Kinoite has no cargo)              → runs in a throwaway
#     container of the devcontainer's own compose service (same image, same
#     `target`/registry volumes, same paths as VS Code → no duplicate build caches)
#
#   make test | check | fmt | run | shell
#
# No optional features are on by default (`flaresolverr`, `ytdlp` are opt-in);
# test/check build them all, matching CI (--all-features).

HAVE_CARGO := $(shell command -v cargo >/dev/null 2>&1 && echo yes)

# Project name = what VS Code uses (<folder>_devcontainer), so the named
# volumes are shared with the editor's devcontainer.
DC = docker compose -p $(notdir $(CURDIR))_devcontainer -f .devcontainer/docker-compose.dev.yml

# $(call cargo,<cargo command>[,<extra `compose run` args>])
ifeq ($(HAVE_CARGO),yes)
cargo = bash -c '$(1)'
else
cargo = $(DC) run --rm $(2) dev bash -c '$(1)'
endif

.PHONY: test check fmt run shell build-image
test:
	$(call cargo,cargo test --all-features)

check:
	$(call cargo,cargo clippy --all-targets --all-features -- -D warnings)

fmt:
	$(call cargo,cargo fmt)

run:
	$(call cargo,cargo run -- --config config.dev.toml,--service-ports)

shell:
	$(call cargo,exec bash,--service-ports)

build-image:
	docker build -t cobweb:latest .
