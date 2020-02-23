use crate::aes128cbc::AES128Cbc;

use core::convert::TryInto;
use s32k144;
use s32k144evb::csec;
use s32k144evb::csec::CommandResult as Error;

pub struct S32k144AES {
    csec: csec::CSEc,
}

impl S32k144AES {
    pub fn new(ftfc: s32k144::FTFC, cse_pram: s32k144::CSE_PRAM) -> Self {
        S32k144AES {
            csec: csec::CSEc::init(ftfc, cse_pram),
        }
    }

    fn impl_encrypt(
        &mut self,
        key: [u8; 16],
        iv: [u8; 16],
        plaintext: &[u8; 16],
        ciphertext: &mut [u8; 16],
    ) -> Result<(), Error> {
        // XXX: do we really have to call `load_plainkey` every time?
        self.csec.load_plainkey(&key)?;
        self.csec.encrypt_cbc(plaintext, &iv, ciphertext)
    }

    fn impl_decrypt(
        &mut self,
        key: [u8; 16],
        iv: [u8; 16],
        ciphertext: &[u8; 16],
        plaintext: &mut [u8; 16],
    ) -> Result<(), Error> {
        self.csec.load_plainkey(&key)?;
        self.csec.decrypt_cbc(ciphertext, &iv, plaintext)
    }
}

impl AES128Cbc for S32k144AES {
    type Error = Error;

    fn encrypt(
        &mut self,
        key: [u8; 16],
        iv: [u8; 16],
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<(), Error> {
        if plaintext.len() % 16 != 0 && plaintext.len() != ciphertext.len() {
            return Err(Error::GeneralError);
        }

        // NOTE(unwrap): With the check above, each chunk will always have the length 16.
        for (plain_chunk, cipher_chunk) in plaintext.chunks(16).zip(ciphertext.chunks_mut(16)) {
            self.impl_encrypt(
                key,
                iv,
                plain_chunk.try_into().unwrap(),
                cipher_chunk.try_into().unwrap(),
            )?;
        }
        Ok(())
    }

    fn decrypt(
        &mut self,
        key: [u8; 16],
        iv: [u8; 16],
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<(), Error> {
        if plaintext.len() % 16 != 0 && plaintext.len() != ciphertext.len() {
            return Err(Error::GeneralError);
        }

        // NOTE(unwrap): With the check above, each chunk will always have the length 16.
        for (plain_chunk, cipher_chunk) in plaintext.chunks_mut(16).zip(ciphertext.chunks(16)) {
            self.impl_decrypt(
                key,
                iv,
                cipher_chunk.try_into().unwrap(),
                plain_chunk.try_into().unwrap(),
            )?;
        }
        Ok(())
    }
}
