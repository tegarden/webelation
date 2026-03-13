.PHONY: check test

# Default target
all: pack

check:
	cd rust && cargo check

test:
	cd rust && cargo test

pack: rust/Cargo.toml rust/src/lib.rs
	cd rust && wasm-pack build --target web --out-dir pkg
