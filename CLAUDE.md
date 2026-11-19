# RustyKey

Rust port of the OnlyKey app. Tauri 2.12 desktop + Leptos 0.8 (CSR, Trunk) UI + `onlykey-core` (pure Rust, native and wasm32).

## Commands
- Test: `cargo test --workspace`
- Lint: `cargo clippy --workspace --all-targets -- -D warnings` and `cargo fmt --all --check`
- Desktop dev: `cargo tauri dev` (needs `cargo install tauri-cli --version ^2 --locked`, `cargo install trunk --locked`, `rustup target add wasm32-unknown-unknown`)
- Desktop build: `cargo tauri build` (quick macOS check: `cargo tauri build --debug --bundles app`)
- Web (ChromeOS) dev: `cd crates/rustykey-ui && trunk serve --no-default-features --features web` (build: `trunk build --release --no-default-features --features web`)
- Core for wasm: `cargo build -p onlykey-core --target wasm32-unknown-unknown`

## Rules
- The original app is in `reference/OnlyKey-App` (gitignored, read-only). Port behaviour from it exactly; `docs/PARITY.md` is the checklist.
- `onlykey-core` has no I/O, no clock, no Tauri, no tokio. It must build for wasm32.
- The UI talks to the device only through the `Backend` trait. Device logic never goes in the UI or src-tauri; put it in core.
- Never log, store or keep secrets (PINs, passphrases, passwords, keys, TOTP seeds, backup text).
- Tray menus are rebuilt in full on change, never edited in place.
- Every fn, struct and module gets a one-line `///` doc comment saying what it does.
- Tauri 2.x only, not the 3.x alpha.

## Docs
`docs/SPEC.md` (design) · `docs/PLAN.md` (tasks) · `docs/PARITY.md` (feature list) · `filemap.md` (where things live)
