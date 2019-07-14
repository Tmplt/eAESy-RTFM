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
#![allow(non_camel_case_types)]

use s32k144;
use s32k144evb::csec;
use s32k144evb::csec::CommandResult as Error;

pub trait AES128Cbc {
    type Error;

    fn encrypt(&mut self, key: [u8; 16], iv: [u8; 16], plaintext: &[u8], cipher: &mut [u8]) -> Result<(), Self::Error>;
    fn decrypt(&mut self, key: [u8; 16], iv: [u8; 16], cipher: &[u8], plaintext: &mut [u8]) -> Result<(), Self::Error>;

    // TODO: default trait implementation is software implementation
    // Notify user if SW-impl is used
}

pub struct s32k144AES {
    csec: csec::CSEc,
}

impl s32k144AES {
    pub fn new(ftfc: s32k144::FTFC, cse_pram: s32k144::CSE_PRAM) -> Self {
        s32k144AES { csec: csec::CSEc::init(ftfc, cse_pram), }
    }
}

impl AES128Cbc for s32k144AES {
    type Error = Error;

    fn encrypt(&mut self, key: [u8; 16], iv: [u8; 16], plaintext: &[u8], cipher: &mut [u8]) -> Result<(), Error> {
        self.csec.load_plainkey(&key)?;
        self.csec.encrypt_cbc(plaintext, &iv, cipher)
    }

    fn decrypt(&mut self, key: [u8; 16], iv: [u8; 16], cipher: &[u8], plaintext: &mut [u8]) -> Result<(), Error> {
        self.csec.load_plainkey(&key)?;
        self.csec.decrypt_cbc(cipher, &iv, plaintext)
    }
}
