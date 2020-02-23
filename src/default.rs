//! Implements the default software implementation
use crate::aes128cbc::AES128Cbc;
use block_cipher_trait::generic_array::GenericArray;
use block_modes::BlockMode;
use block_modes::BlockModeError as Error;

type SwAES128Cbc = block_modes::Cbc<aes::Aes128, block_modes::block_padding::Pkcs7>;

pub struct SoftwareAES;

impl SoftwareAES {
    pub fn new() -> Self {
        SoftwareAES {}
    }
}

impl AES128Cbc for SoftwareAES {
    type Error = Error;

    fn encrypt(
        &mut self,
        key: [u8; 16],
        iv: [u8; 16],
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<(), Self::Error> {
        if plaintext.len() % 16 != 0 && plaintext.len() != ciphertext.len() {
            return Err(Error);
        }

        let cipher = SwAES128Cbc::new_fix(
            GenericArray::from_slice(&key),
            GenericArray::from_slice(&iv),
        );

        // This software implementation works in-place: `ciphertext` acts as our buffer.
        // XXX: `plaintext` will temporarily be stored in `ciphertext`.
        let pos = plaintext.len();
        ciphertext[..pos].copy_from_slice(plaintext);

        cipher.encrypt(ciphertext, pos)?;
        Ok(())
    }

    fn decrypt(
        &mut self,
        key: [u8; 16],
        iv: [u8; 16],
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<(), Self::Error> {
        if plaintext.len() % 16 != 0 && plaintext.len() != ciphertext.len() {
            return Err(Error);
        }

        let cipher = SwAES128Cbc::new_fix(
            GenericArray::from_slice(&key),
            GenericArray::from_slice(&iv),
        );
        plaintext.copy_from_slice(ciphertext);
        cipher.decrypt(plaintext)?;

        Ok(())
    }
}
