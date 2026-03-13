# Revelation Web Viewer

## Project Overview

This project provides a **web-based viewer for password files created by the Revelation password manager**. The goal is to allow users to **open and inspect an existing Revelation password file directly in a browser**, without installing the original desktop application.

The application is **read-only**. It will **not modify or write password files**. Its only purpose is to parse an existing file and present its contents in a user-friendly format.

The implementation is split into two main parts:

* **Rust WebAssembly module (`rust/`)**
  Responsible for parsing the Revelation file format and returning a structured representation of its contents.

* **Web frontend (`web/`)**
  Responsible for user interaction, including selecting a file and displaying the parsed contents.

All file parsing and cryptographic operations occur inside the WebAssembly module.

---

# Architecture

```
User selects file
      │
      ▼
Browser (HTML / JS)
      │
      ▼
Rust WebAssembly module
      │
      ▼
Parse Revelation file
      │
      ▼
Return JSON structure
      │
      ▼
Frontend renders readable view
```

The frontend **does not parse the file format itself**. All file-format logic lives in Rust.

---

# Repository Structure

```
.
├─ README.md
├─ rust/        # Rust crate compiled to WebAssembly
│  ├─ Cargo.toml
│  └─ src/
│     └─ lib.rs
└─ web/         # HTML / JavaScript frontend
```

## `rust/`

Contains the Rust implementation that:

* accepts Revelation file data
* decrypts and parses the file
* converts the internal representation to JSON
* exposes the functionality to JavaScript via WebAssembly bindings

Expected public interface (conceptual):

```
parse_revelation(data: Uint8Array, password: string) -> JSON
```

The Rust crate will be compiled to WebAssembly and imported by the frontend.

## `web/`

Contains the browser UI:

* HTML page
* JavaScript code
* file chooser
* password prompt
* rendering of parsed data

The frontend:

1. Reads the file selected by the user
2. Passes the file data to the WebAssembly module
3. Receives JSON output
4. Displays the contents in a readable format

---

# Security Goals

* Password files are **processed entirely within the browser**
* No network requests are required to parse files
* No passwords or decrypted secrets leave the user's machine
* The application performs **read-only inspection** of files

---

# Development Guidelines

General principles:

* Keep **file-format logic in Rust**
* Keep **UI logic in JavaScript**
* Avoid duplicating parsing logic in the frontend
* Keep the WebAssembly interface small and well defined

Rust code should:

* prefer safe Rust
* use clear error handling
* return structured JSON suitable for UI rendering

Frontend code should:

* avoid unnecessary dependencies
* keep the UI simple and readable
* treat the Rust module as the source of truth for parsing

