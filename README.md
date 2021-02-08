# Lamport Signature
[![crates.io badge](https://img.shields.io/crates/v/lamport-sig.svg)](https://crates.io/crates/lamport-sig)
![Rust](https://github.com/NoCtrlZ/lamport-signature/workflows/Rust/badge.svg)  
This is the lamport signature rust client.

## Usage

```rust
let plain_text = "secret message";
let private_key = key::PrivateKey::new();
let signature = private_key.sign(&plain_text);
let public_key = private_key.to_public_key();
let is_valid = public_key.verify(plain_text, signature);
assert_eq!(true, is_valid);
```

## Installation
```toml
[dependencies]
lamport-sig = "0.1.1"
```

## Test
```
$ cargo test
```
