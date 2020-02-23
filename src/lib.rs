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

#[cfg(feature = "software")]
pub mod default;

#[cfg(feature = "s32k144evb-q100")]
pub mod s32k144;
