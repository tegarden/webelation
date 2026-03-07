use wasm_bindgen::prelude::*;

/// Parse a Revelation file payload and return a JSON document.
///
/// This is currently a stub implementation:
/// - `data` is accepted for API shape compatibility, but ignored
/// - always returns an empty JSON object (`{}`)
#[wasm_bindgen]
pub fn parse_revelation(data: &[u8], password: &str) -> String {
    let _ = data;
    let _ = password;
    "{}".to_string()
}

#[cfg(test)]
mod tests {
    use super::parse_revelation;
    use std::fs;
    use std::path::PathBuf;

    fn fixture_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join(name)
    }

    fn load_fixture(name: &str) -> Vec<u8> {
        fs::read(fixture_path(name)).expect("fixture should be readable")
    }

    #[test]
    fn parse_revelation_returns_empty_json_for_empty_fixture() {
        let data = load_fixture("empty.revelation");
        let output = parse_revelation(&data, "");

        assert_eq!(output, "{}");
    }
}
