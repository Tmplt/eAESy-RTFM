//! Traits for AES-CBC-128 encryption/decryption
//!
//! From some other crate we should be able to
//! ```
//! [dependencies.aesy-rtfm]
//! git = "..."
//! device = "s32k144"
//! ```
//! and in code we can then call... what, exactly?
//! ```
//! AES128Cbc::decrypt(...) // ?
//! ```
#![no_std]

pub mod aes128cbc;
pub mod default;
pub mod s32k144;
