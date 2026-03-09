default:
    @just --list

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all -- --check

clippy:
    cargo clippy --all-targets --all-features -- -D warnings

check:
    cargo check --all-targets

test:
    cargo test --all

build:
    cargo build --release

install: build
    #!/usr/bin/env bash
    set -euo pipefail
    cp target/release/xmit ~/.local/bin/xmit
    echo "installed xmit to ~/.local/bin/"

ci: fmt-check clippy test
