export CARGO_TERM_COLOR := "always"

default:
    @just --list

# ── Build ─────────────────────────────────────────────────────────────
build:
    cargo build --all-targets

build-release:
    cargo build --all-targets --release

check:
    cargo check --all-targets

# ── Format ────────────────────────────────────────────────────────────
fmt:
    cargo fmt

fmt-check:
    cargo fmt -- --check

# ── Lint ──────────────────────────────────────────────────────────────
lint:
    cargo clippy --all-targets

lint-strict:
    cargo clippy --all-targets -- -D warnings

lint-fix:
    cargo clippy --all-targets --fix --allow-dirty --allow-staged

fix:
    cargo fix --all-targets --allow-dirty --allow-staged
    cargo clippy --all-targets --fix --allow-dirty --allow-staged
    cargo fmt

# ── Test ──────────────────────────────────────────────────────────────
test:
    cargo test

# ── Aggregate ─────────────────────────────────────────────────────────
ci: fmt-check check lint-strict test

pre-commit: fmt check lint-strict test

clean:
    cargo clean
