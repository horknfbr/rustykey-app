//! OnlyKey protocol, device engine and data handling. Pure Rust: no I/O, no clock; builds for native and wasm32.

pub mod api;
pub mod backup;
pub mod device_type;
pub mod encoding;
pub mod engine;
pub mod firmware;
pub mod keys;
pub mod onepassword;
pub mod parser;
pub mod password;
pub mod protocol;
pub mod slot;
pub mod transport;

/// Crate version, from Cargo.toml.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    //! Smoke test so `cargo test` has something to run.

    /// The version constant matches the workspace version.
    #[test]
    fn version_is_set() {
        assert_eq!(super::VERSION, "0.1.0");
    }
}
