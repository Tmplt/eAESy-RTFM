//! This crate exposes a trait for hardware-accelerated AES-128-CBC encryption/decryption on
//! `no-std` targets with available support. As a fallback, for targets that lack a cryptography
//! engine, a software implementation can be used instead. Arbitrary input lengths are supported
//! via PKCS7 padding.
//!
//! At present, this crate utilizes the cryptography engines on the following targets:
//! - NXP S32K144EVB-Q100 (`s32k144evb-q100` feature)
//!
//! The implementation expects a pre-allocated buffer in which data is encrypted/decrypted
//! in-place.
//!
//! Example usage:
//! ```
//! #[macro_use]
//! extern crate hex_literal;
//!
//! use easy::{aes128cbc::AES128Cbc, default::SoftwareAES};
//!
//! // ...
//!
//! let key = hex!("000102030405060708090a0b0c0d0e0f");
//! let iv = hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
//! let plaintext = b"Hello world!";
//!
//! let pos = plaintext.len();
//! let buffer = [0; 16]; // must be a multiple of 16B; round up to account for padding
//! buffer[..pos].copy_from_slice(plaintext);
//!
//! let mut aes = SoftwareAES::new(); // arguments to `new` will depend on implementation used
//! let _ciphertext = aes.encrypt(key, iv, &mut buffer, pos).unwrap()l;
//! let decrypted_ciphertext = aes.decrypt(key, iv, &mut buffer).unwrap();
//!
//! assert_eq!(plaintext, decrypted_ciphertext);
//! ```
#![no_std]

pub mod aes128cbc;

#[cfg(feature = "software")]
pub mod default;

#[cfg(feature = "s32k144evb-q100")]
pub mod s32k144;
