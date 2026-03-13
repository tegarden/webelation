use aes::Aes256;
use cbc::cipher::block_padding::NoPadding;
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use cbc::Decryptor;
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
    pbkdf2_hmac::<Sha1>(password.as_bytes(), salt, PBKDF2_ITERATIONS, &mut key);
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

fn parse_revelation_xml(file_data: &[u8], password: &str) -> Result<Element, RevelationParseError> {
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

fn field_value(element: &Element, field_id: &str) -> Option<String> {
    child_elements(element, "field")
        .into_iter()
        .find_map(|field| {
            let matches = field
                .attributes
                .get("id")
                .map(String::as_str)
                .is_some_and(|id| id == field_id);

            if matches {
                field.get_text().map(|text| text.to_string())
            } else {
                None
            }
        })
}

fn insert_optional_string(object: &mut Map<String, Value>, key: &str, value: Option<String>) {
    object.insert(
        key.to_string(),
        value.map(Value::String).unwrap_or(Value::Null),
    );
}

fn node_label(element: &Element) -> String {
    first_child_text(element, "name").unwrap_or_else(|| "Untitled".to_string())
}

fn entry_to_json(element: &Element, id: String) -> Value {
    let entry_type = element
        .attributes
        .get("type")
        .map(String::as_str)
        .unwrap_or("");
    let label = node_label(element);
    let description = first_child_text(element, "description");
    let notes = first_child_text(element, "notes").or_else(|| description.clone());

    let mut object = Map::new();
    object.insert("id".to_string(), Value::String(id.clone()));
    object.insert("type".to_string(), Value::String(entry_type.to_string()));
    object.insert("label".to_string(), Value::String(label.clone()));
    object.insert("title".to_string(), Value::String(label));
    insert_optional_string(&mut object, "description", description);
    insert_optional_string(&mut object, "notes", notes);

    if entry_type == "folder" {
        let children = child_elements(element, "entry")
            .into_iter()
            .enumerate()
            .map(|(index, child)| entry_to_json(child, format!("{id}.{index}")))
            .collect::<Vec<Value>>();
        object.insert("nodeType".to_string(), Value::String("folder".to_string()));
        object.insert("children".to_string(), Value::Array(children));
    } else {
        let username = field_value(element, "generic-username")
            .or_else(|| field_value(element, "generic-email"));
        let password = field_value(element, "generic-password");
        let url = field_value(element, "generic-url")
            .or_else(|| field_value(element, "generic-hostname"));

        object.insert("nodeType".to_string(), Value::String("entry".to_string()));
        insert_optional_string(&mut object, "username", username);
        insert_optional_string(&mut object, "password", password);
        insert_optional_string(&mut object, "url", url);
        insert_optional_string(&mut object, "cardType", field_value(element, "creditcard-cardtype"));
        insert_optional_string(
            &mut object,
            "cardNumber",
            field_value(element, "creditcard-cardnumber"),
        );
        insert_optional_string(
            &mut object,
            "expiryDate",
            field_value(element, "creditcard-expirydate"),
        );
        insert_optional_string(&mut object, "ccv", field_value(element, "creditcard-ccv"));
        insert_optional_string(
            &mut object,
            "pin",
            field_value(element, "creditcard-pin")
                .or_else(|| field_value(element, "generic-pin"))
                .or_else(|| field_value(element, "creditcard-pincode")),
        );
        insert_optional_string(
            &mut object,
            "location",
            field_value(element, "generic-location"),
        );
        insert_optional_string(&mut object, "code", field_value(element, "generic-code"));
    }

    Value::Object(object)
}

fn revelation_tree_to_json_string(root: &Element) -> String {
    let entries = child_elements(root, "entry")
        .into_iter()
        .enumerate()
        .map(|(index, entry)| entry_to_json(entry, index.to_string()))
        .collect::<Vec<Value>>();

    let mut object = Map::new();
    object.insert("entries".to_string(), Value::Array(entries));
    serde_json::to_string(&Value::Object(object)).unwrap_or_else(|_| "{\"entries\":[]}".to_string())
}

/// Parse a Revelation file payload and return a JSON document.
#[wasm_bindgen]
pub fn parse_revelation(data: &[u8], password: &str) -> String {
    match parse_revelation_xml(data, password) {
        Ok(root) => revelation_tree_to_json_string(&root),
        Err(error) => {
            let mut object = Map::new();
            object.insert("error".to_string(), Value::String(error.to_string()));
            serde_json::to_string(&Value::Object(object))
                .unwrap_or_else(|_| "{\"error\":\"unknown parse error\"}".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        child_elements, first_child_text, parse_revelation, parse_revelation_xml,
        RevelationParseError,
    };
    use serde_json::Value;
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

    fn json_pointer_str<'a>(value: &'a Value, pointer: &str) -> Option<&'a str> {
        value.pointer(pointer).and_then(Value::as_str)
    }

    #[test]
    fn parse_revelation_returns_empty_entries_for_empty_fixture() {
        let data = load_fixture("empty.revelation");
        let output = parse_revelation(&data, "foo");

        assert_eq!(output, "{\"entries\":[]}");
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
        assert_eq!(
            entry_one.attributes.get("type").map(String::as_str),
            Some("generic")
        );
        assert_eq!(
            first_child_text(entry_one, "name").as_deref(),
            Some("Entry 1")
        );
        assert_eq!(
            first_child_text(entry_one, "description").as_deref(),
            Some("entry one")
        );
        assert_eq!(first_child_text(entry_one, "notes").as_deref(), Some("qux"));
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
        assert_eq!(
            folder.attributes.get("type").map(String::as_str),
            Some("folder")
        );
        assert_eq!(
            first_child_text(folder, "name").as_deref(),
            Some("Folder 1")
        );
        assert_eq!(
            first_child_text(folder, "description").as_deref(),
            Some("quux")
        );

        let nested_entries = child_elements(folder, "entry");
        assert_eq!(nested_entries.len(), 1);
        let entry_two = nested_entries[0];
        assert_eq!(
            entry_two.attributes.get("type").map(String::as_str),
            Some("website")
        );
        assert_eq!(
            first_child_text(entry_two, "name").as_deref(),
            Some("Entry 2")
        );
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

        assert_eq!(
            json_pointer_str(&json, "/entries/0/nodeType"),
            Some("entry")
        );
        assert_eq!(json_pointer_str(&json, "/entries/0/type"), Some("generic"));
        assert_eq!(json_pointer_str(&json, "/entries/0/title"), Some("Entry 1"));
        assert_eq!(
            json_pointer_str(&json, "/entries/0/description"),
            Some("entry one")
        );
        assert_eq!(json_pointer_str(&json, "/entries/0/notes"), Some("qux"));
        assert_eq!(json_pointer_str(&json, "/entries/0/url"), Some("foo"));
        assert_eq!(json_pointer_str(&json, "/entries/0/username"), Some("bar"));
        assert_eq!(json_pointer_str(&json, "/entries/0/password"), Some("baz"));

        assert_eq!(
            json_pointer_str(&json, "/entries/1/nodeType"),
            Some("folder")
        );
        assert_eq!(json_pointer_str(&json, "/entries/1/type"), Some("folder"));
        assert_eq!(
            json_pointer_str(&json, "/entries/1/title"),
            Some("Folder 1")
        );
        assert_eq!(json_pointer_str(&json, "/entries/1/notes"), Some("quux"));
        assert_eq!(
            json_pointer_str(&json, "/entries/1/children/0/nodeType"),
            Some("entry")
        );
        assert_eq!(
            json_pointer_str(&json, "/entries/1/children/0/title"),
            Some("Entry 2")
        );
        assert_eq!(
            json_pointer_str(&json, "/entries/1/children/0/description"),
            Some("entry two")
        );
        assert_eq!(
            json_pointer_str(&json, "/entries/1/children/0/notes"),
            Some("quuuuux")
        );
        assert_eq!(
            json_pointer_str(&json, "/entries/1/children/0/url"),
            Some("http://example.com/")
        );
        assert_eq!(
            json_pointer_str(&json, "/entries/1/children/0/username"),
            Some("quuux")
        );
        assert_eq!(
            json_pointer_str(&json, "/entries/1/children/0/password"),
            Some("quuuux")
        );
    }

    #[test]
    fn parse_revelation_returns_error_json_for_wrong_password() {
        let data = load_fixture("simple.revelation");
        let output = parse_revelation(&data, "wrong-password");
        let json: Value = serde_json::from_str(&output).expect("expected valid JSON");

        assert_eq!(
            json_pointer_str(&json, "/error"),
            Some("integrity hash mismatch")
        );
    }

    #[test]
    fn parse_revelation_reads_creditcard_fixture_as_json() {
        let data = load_fixture("creditcard.revelation");
        let output = parse_revelation(&data, "abc");
        let json: Value = serde_json::from_str(&output).expect("expected valid JSON");

        assert_eq!(json_pointer_str(&json, "/entries/0/type"), Some("creditcard"));
        assert_eq!(
            json_pointer_str(&json, "/entries/0/description"),
            Some("My Description")
        );
        assert_eq!(json_pointer_str(&json, "/entries/0/cardType"), Some("Visa"));
        assert_eq!(
            json_pointer_str(&json, "/entries/0/cardNumber"),
            Some("1211109876543210")
        );
        assert_eq!(json_pointer_str(&json, "/entries/0/expiryDate"), Some("12/34"));
        assert_eq!(json_pointer_str(&json, "/entries/0/ccv"), Some("567"));
        assert_eq!(json_pointer_str(&json, "/entries/0/pin"), Some("8901"));
        assert_eq!(json_pointer_str(&json, "/entries/0/notes"), Some("My Notes"));
    }

    #[test]
    fn parse_revelation_reads_door_fixture_as_json() {
        let data = load_fixture("door.revelation");
        let output = parse_revelation(&data, "abc");
        let json: Value = serde_json::from_str(&output).expect("expected valid JSON");

        assert_eq!(json_pointer_str(&json, "/entries/0/type"), Some("door"));
        assert_eq!(
            json_pointer_str(&json, "/entries/0/description"),
            Some("My Description")
        );
        assert_eq!(json_pointer_str(&json, "/entries/0/location"), Some("My Location"));
        assert_eq!(json_pointer_str(&json, "/entries/0/code"), Some("1234"));
        assert_eq!(json_pointer_str(&json, "/entries/0/notes"), Some("My Notes"));
    }
}
