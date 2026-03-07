use aes::Aes256;
use cbc::Decryptor;
use cbc::cipher::block_padding::NoPadding;
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use flate2::read::ZlibDecoder;
use pbkdf2::pbkdf2_hmac;
use serde_json::{Map, Value};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::io::Read;
use wasm_bindgen::prelude::*;
use xmltree::{Element, XMLNode};

const HEADER_LEN: usize = 12;
const SALT_LEN: usize = 8;
const IV_LEN: usize = 16;
const SHA256_LEN: usize = 32;
const AES_BLOCK_SIZE: usize = 16;
const PBKDF2_ITERATIONS: u32 = 12_000;
const KEY_LEN: usize = 32;
const MAGIC: &[u8; 4] = b"rvl\0";
const DATA_FORMAT_VERSION: u8 = 0x02;

#[derive(Debug, thiserror::Error)]
pub enum RevelationParseError {
    #[error("file is too short to contain a Revelation v2 header")]
    FileTooShort,
    #[error("invalid magic header, expected \"rvl\\0\"")]
    InvalidMagic,
    #[error("unsupported data format version: {0:#04x}")]
    UnsupportedVersion(u8),
    #[error("ciphertext is empty")]
    EmptyCiphertext,
    #[error("ciphertext length is not a multiple of 16 bytes")]
    InvalidCiphertextLength,
    #[error("unable to initialize AES-CBC decryptor")]
    DecryptorInit,
    #[error("AES-CBC decryption failed")]
    DecryptionFailed,
    #[error("decrypted payload is too short for integrity hash")]
    DecryptedPayloadTooShort,
    #[error("integrity hash mismatch")]
    IntegrityMismatch,
    #[error("invalid PKCS#7 padding")]
    InvalidPadding,
    #[error("zlib decompression failed")]
    DecompressionFailed,
    #[error("xml parse failed")]
    XmlParseFailed,
    #[error("unexpected XML root element: {0}")]
    UnexpectedRoot(String),
}

struct EncryptedSections<'a> {
    salt: &'a [u8],
    iv: &'a [u8],
    ciphertext: &'a [u8],
}

fn parse_sections(file_data: &[u8]) -> Result<EncryptedSections<'_>, RevelationParseError> {
    if file_data.len() < HEADER_LEN + SALT_LEN + IV_LEN {
        return Err(RevelationParseError::FileTooShort);
    }

    if &file_data[0..4] != MAGIC {
        return Err(RevelationParseError::InvalidMagic);
    }

    let version = file_data[4];
    if version != DATA_FORMAT_VERSION {
        return Err(RevelationParseError::UnsupportedVersion(version));
    }

    let salt_start = HEADER_LEN;
    let salt_end = salt_start + SALT_LEN;
    let iv_end = salt_end + IV_LEN;

    let salt = &file_data[salt_start..salt_end];
    let iv = &file_data[salt_end..iv_end];
    let ciphertext = &file_data[iv_end..];

    if ciphertext.is_empty() {
        return Err(RevelationParseError::EmptyCiphertext);
    }

    if ciphertext.len() % AES_BLOCK_SIZE != 0 {
        return Err(RevelationParseError::InvalidCiphertextLength);
    }

    Ok(EncryptedSections {
        salt,
        iv,
        ciphertext,
    })
}

fn derive_key(password: &str, salt: &[u8]) -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    pbkdf2_hmac::<Sha1>(
        password.as_bytes(),
        salt,
        PBKDF2_ITERATIONS,
        &mut key,
    );
    key
}

fn decrypt_payload(
    ciphertext: &[u8],
    key: &[u8; KEY_LEN],
    iv: &[u8],
) -> Result<Vec<u8>, RevelationParseError> {
    let mut decrypted = ciphertext.to_vec();

    let decryptor = Decryptor::<Aes256>::new_from_slices(key, iv)
        .map_err(|_| RevelationParseError::DecryptorInit)?;
    decryptor
        .decrypt_padded_mut::<NoPadding>(&mut decrypted)
        .map_err(|_| RevelationParseError::DecryptionFailed)?;

    Ok(decrypted)
}

fn strip_pkcs7_padding(data: &[u8]) -> Result<&[u8], RevelationParseError> {
    let Some(&last_byte) = data.last() else {
        return Err(RevelationParseError::InvalidPadding);
    };

    let pad_len = last_byte as usize;
    if pad_len == 0 || pad_len > AES_BLOCK_SIZE || pad_len > data.len() {
        return Err(RevelationParseError::InvalidPadding);
    }

    let padding = &data[data.len() - pad_len..];
    if !padding.iter().all(|&byte| byte as usize == pad_len) {
        return Err(RevelationParseError::InvalidPadding);
    }

    Ok(&data[..data.len() - pad_len])
}

fn decompress_zlib(data: &[u8]) -> Result<Vec<u8>, RevelationParseError> {
    let mut decoder = ZlibDecoder::new(data);
    let mut decompressed = Vec::new();
    decoder
        .read_to_end(&mut decompressed)
        .map_err(|_| RevelationParseError::DecompressionFailed)?;
    Ok(decompressed)
}

fn parse_xml_tree(xml_bytes: &[u8]) -> Result<Element, RevelationParseError> {
    let root = Element::parse(xml_bytes).map_err(|_| RevelationParseError::XmlParseFailed)?;
    if root.name != "revelationdata" {
        return Err(RevelationParseError::UnexpectedRoot(root.name));
    }

    Ok(root)
}

fn parse_revelation_xml(
    file_data: &[u8],
    password: &str,
) -> Result<Element, RevelationParseError> {
    let sections = parse_sections(file_data)?;
    let key = derive_key(password, sections.salt);
    let decrypted = decrypt_payload(sections.ciphertext, &key, sections.iv)?;

    if decrypted.len() < SHA256_LEN {
        return Err(RevelationParseError::DecryptedPayloadTooShort);
    }

    let (stored_hash, payload_with_padding) = decrypted.split_at(SHA256_LEN);
    let computed_hash = Sha256::digest(payload_with_padding);
    if computed_hash.as_slice() != stored_hash {
        return Err(RevelationParseError::IntegrityMismatch);
    }

    let compressed_payload = strip_pkcs7_padding(payload_with_padding)?;
    let xml_bytes = decompress_zlib(compressed_payload)?;
    parse_xml_tree(&xml_bytes)
}

fn xml_element_to_json(element: &Element) -> Value {
    let mut object = Map::new();
    object.insert("name".to_string(), Value::String(element.name.clone()));

    let attributes = element
        .attributes
        .iter()
        .map(|(key, value)| (key.clone(), Value::String(value.clone())))
        .collect::<Map<String, Value>>();
    object.insert("attributes".to_string(), Value::Object(attributes));

    let children = element
        .children
        .iter()
        .map(xml_node_to_json)
        .collect::<Vec<Value>>();
    object.insert("children".to_string(), Value::Array(children));

    Value::Object(object)
}

fn xml_node_to_json(node: &XMLNode) -> Value {
    match node {
        XMLNode::Element(element) => xml_element_to_json(element),
        XMLNode::Text(text) => {
            let mut object = Map::new();
            object.insert("type".to_string(), Value::String("text".to_string()));
            object.insert("value".to_string(), Value::String(text.clone()));
            Value::Object(object)
        }
        XMLNode::CData(text) => {
            let mut object = Map::new();
            object.insert("type".to_string(), Value::String("cdata".to_string()));
            object.insert("value".to_string(), Value::String(text.clone()));
            Value::Object(object)
        }
        XMLNode::Comment(text) => {
            let mut object = Map::new();
            object.insert("type".to_string(), Value::String("comment".to_string()));
            object.insert("value".to_string(), Value::String(text.clone()));
            Value::Object(object)
        }
        XMLNode::ProcessingInstruction(target, value) => {
            let mut object = Map::new();
            object.insert(
                "type".to_string(),
                Value::String("processing_instruction".to_string()),
            );
            object.insert("target".to_string(), Value::String(target.clone()));
            match value {
                Some(value) => {
                    object.insert("value".to_string(), Value::String(value.clone()));
                }
                None => {
                    object.insert("value".to_string(), Value::Null);
                }
            }
            Value::Object(object)
        }
    }
}

fn xml_tree_to_json_string(root: &Element) -> String {
    if root.name == "revelationdata" && root.children.is_empty() {
        return "{}".to_string();
    }

    let json = xml_element_to_json(root);
    serde_json::to_string(&json).unwrap_or_else(|_| "{}".to_string())
}

/// Parse a Revelation file payload and return a JSON document.
///
/// This is currently a stub implementation:
/// - `data` is accepted for API shape compatibility, but ignored
/// - always returns an empty JSON object (`{}`)
#[wasm_bindgen]
pub fn parse_revelation(data: &[u8], password: &str) -> String {
    match parse_revelation_xml(data, password) {
        Ok(root) => xml_tree_to_json_string(&root),
        Err(_) => "{}".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_revelation, parse_revelation_xml, RevelationParseError};
    use serde_json::Value;
    use std::fs;
    use std::path::PathBuf;
    use xmltree::{Element, XMLNode};

    fn fixture_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join(name)
    }

    fn load_fixture(name: &str) -> Vec<u8> {
        fs::read(fixture_path(name)).expect("fixture should be readable")
    }

    fn child_elements<'a>(element: &'a Element, name: &str) -> Vec<&'a Element> {
        element
            .children
            .iter()
            .filter_map(|node| match node {
                XMLNode::Element(child) if child.name == name => Some(child),
                _ => None,
            })
            .collect()
    }

    fn first_child_text(element: &Element, name: &str) -> Option<String> {
        child_elements(element, name).into_iter().find_map(|child| {
            child.children.iter().find_map(|node| match node {
                XMLNode::Text(text) => Some(text.clone()),
                _ => None,
            })
        })
    }

    fn json_pointer_str<'a>(value: &'a Value, pointer: &str) -> Option<&'a str> {
        value.pointer(pointer).and_then(Value::as_str)
    }

    #[test]
    fn parse_revelation_returns_empty_json_for_empty_fixture() {
        let data = load_fixture("empty.revelation");
        let output = parse_revelation(&data, "foo");

        assert_eq!(output, "{}");
    }

    #[test]
    fn parse_revelation_xml_accepts_correct_password_for_empty_fixture() {
        let data = load_fixture("empty.revelation");
        let root = parse_revelation_xml(&data, "foo").expect("expected fixture to decrypt");

        assert_eq!(root.name, "revelationdata");
        assert!(root.children.is_empty());
    }

    #[test]
    fn parse_revelation_xml_rejects_wrong_password_for_empty_fixture() {
        let data = load_fixture("empty.revelation");
        let error =
            parse_revelation_xml(&data, "not-the-password").expect_err("expected decrypt failure");

        assert!(matches!(error, RevelationParseError::IntegrityMismatch));
    }

    #[test]
    fn parse_revelation_xml_reads_simple_fixture() {
        let data = load_fixture("simple.revelation");
        let root = parse_revelation_xml(&data, "abc").expect("expected fixture to decrypt");

        assert_eq!(root.name, "revelationdata");
        assert_eq!(
            root.attributes.get("version").map(String::as_str),
            Some("0.5.6")
        );
        assert_eq!(
            root.attributes.get("dataversion").map(String::as_str),
            Some("1")
        );

        let top_entries = child_elements(&root, "entry");
        assert_eq!(top_entries.len(), 2);

        let entry_one = top_entries[0];
        assert_eq!(entry_one.attributes.get("type").map(String::as_str), Some("generic"));
        assert_eq!(first_child_text(entry_one, "name").as_deref(), Some("Entry 1"));
        assert_eq!(
            first_child_text(entry_one, "description").as_deref(),
            Some("entry one")
        );
        assert_eq!(
            first_child_text(entry_one, "notes").as_deref(),
            Some("qux")
        );
        let entry_one_fields = child_elements(entry_one, "field");
        assert_eq!(entry_one_fields.len(), 3);
        assert_eq!(
            entry_one_fields[0].attributes.get("id").map(String::as_str),
            Some("generic-hostname")
        );
        assert_eq!(entry_one_fields[0].get_text().as_deref(), Some("foo"));
        assert_eq!(
            entry_one_fields[1].attributes.get("id").map(String::as_str),
            Some("generic-username")
        );
        assert_eq!(entry_one_fields[1].get_text().as_deref(), Some("bar"));
        assert_eq!(
            entry_one_fields[2].attributes.get("id").map(String::as_str),
            Some("generic-password")
        );
        assert_eq!(entry_one_fields[2].get_text().as_deref(), Some("baz"));

        let folder = top_entries[1];
        assert_eq!(folder.attributes.get("type").map(String::as_str), Some("folder"));
        assert_eq!(first_child_text(folder, "name").as_deref(), Some("Folder 1"));
        assert_eq!(
            first_child_text(folder, "description").as_deref(),
            Some("quux")
        );

        let nested_entries = child_elements(folder, "entry");
        assert_eq!(nested_entries.len(), 1);
        let entry_two = nested_entries[0];
        assert_eq!(entry_two.attributes.get("type").map(String::as_str), Some("website"));
        assert_eq!(first_child_text(entry_two, "name").as_deref(), Some("Entry 2"));
        assert_eq!(
            first_child_text(entry_two, "description").as_deref(),
            Some("entry two")
        );
        assert_eq!(
            first_child_text(entry_two, "notes").as_deref(),
            Some("quuuuux")
        );

        let fields = child_elements(entry_two, "field");
        assert_eq!(fields.len(), 4);
        assert_eq!(
            fields[0].attributes.get("id").map(String::as_str),
            Some("generic-url")
        );
        assert_eq!(fields[0].get_text().as_deref(), Some("http://example.com/"));
        assert_eq!(
            fields[1].attributes.get("id").map(String::as_str),
            Some("generic-username")
        );
        assert_eq!(fields[1].get_text().as_deref(), Some("quuux"));
        assert_eq!(
            fields[2].attributes.get("id").map(String::as_str),
            Some("generic-email")
        );
        assert_eq!(fields[2].get_text().as_deref(), Some("example@example.com"));
        assert_eq!(
            fields[3].attributes.get("id").map(String::as_str),
            Some("generic-password")
        );
        assert_eq!(fields[3].get_text().as_deref(), Some("quuuux"));
    }

    #[test]
    fn parse_revelation_reads_simple_fixture_as_json() {
        let data = load_fixture("simple.revelation");
        let output = parse_revelation(&data, "abc");
        let json: Value = serde_json::from_str(&output).expect("expected valid JSON");

        assert_eq!(json_pointer_str(&json, "/name"), Some("revelationdata"));
        assert_eq!(json_pointer_str(&json, "/attributes/version"), Some("0.5.6"));
        assert_eq!(json_pointer_str(&json, "/attributes/dataversion"), Some("1"));

        assert_eq!(json_pointer_str(&json, "/children/0/name"), Some("entry"));
        assert_eq!(json_pointer_str(&json, "/children/0/attributes/type"), Some("generic"));
        assert_eq!(
            json_pointer_str(&json, "/children/0/children/0/children/0/value"),
            Some("Entry 1")
        );
        assert_eq!(
            json_pointer_str(&json, "/children/0/children/1/children/0/value"),
            Some("entry one")
        );
        assert_eq!(
            json_pointer_str(&json, "/children/0/children/3/children/0/value"),
            Some("qux")
        );
        assert_eq!(
            json_pointer_str(&json, "/children/0/children/4/attributes/id"),
            Some("generic-hostname")
        );
        assert_eq!(
            json_pointer_str(&json, "/children/0/children/4/children/0/value"),
            Some("foo")
        );
        assert_eq!(
            json_pointer_str(&json, "/children/0/children/5/attributes/id"),
            Some("generic-username")
        );
        assert_eq!(
            json_pointer_str(&json, "/children/0/children/5/children/0/value"),
            Some("bar")
        );
        assert_eq!(
            json_pointer_str(&json, "/children/0/children/6/attributes/id"),
            Some("generic-password")
        );
        assert_eq!(
            json_pointer_str(&json, "/children/0/children/6/children/0/value"),
            Some("baz")
        );

        assert_eq!(json_pointer_str(&json, "/children/1/name"), Some("entry"));
        assert_eq!(json_pointer_str(&json, "/children/1/attributes/type"), Some("folder"));
        assert_eq!(
            json_pointer_str(&json, "/children/1/children/0/children/0/value"),
            Some("Folder 1")
        );
        assert_eq!(
            json_pointer_str(&json, "/children/1/children/1/children/0/value"),
            Some("quux")
        );
        assert_eq!(
            json_pointer_str(&json, "/children/1/children/4/children/0/name"),
            Some("name")
        );
        assert_eq!(
            json_pointer_str(&json, "/children/1/children/4/children/0/children/0/value"),
            Some("Entry 2")
        );
        assert_eq!(
            json_pointer_str(&json, "/children/1/children/4/children/1/children/0/value"),
            Some("entry two")
        );
        assert_eq!(
            json_pointer_str(&json, "/children/1/children/4/children/3/children/0/value"),
            Some("quuuuux")
        );
        assert_eq!(
            json_pointer_str(&json, "/children/1/children/4/children/4/attributes/id"),
            Some("generic-url")
        );
        assert_eq!(
            json_pointer_str(&json, "/children/1/children/4/children/4/children/0/value"),
            Some("http://example.com/")
        );
        assert_eq!(
            json_pointer_str(&json, "/children/1/children/4/children/5/attributes/id"),
            Some("generic-username")
        );
        assert_eq!(
            json_pointer_str(&json, "/children/1/children/4/children/5/children/0/value"),
            Some("quuux")
        );
        assert_eq!(
            json_pointer_str(&json, "/children/1/children/4/children/6/attributes/id"),
            Some("generic-email")
        );
        assert_eq!(
            json_pointer_str(&json, "/children/1/children/4/children/6/children/0/value"),
            Some("example@example.com")
        );
        assert_eq!(
            json_pointer_str(&json, "/children/1/children/4/children/7/attributes/id"),
            Some("generic-password")
        );
        assert_eq!(
            json_pointer_str(&json, "/children/1/children/4/children/7/children/0/value"),
            Some("quuuux")
        );
    }
}
