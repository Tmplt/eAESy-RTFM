//! Software implementation of `Aes128Cbc`.
use crate::aes128cbc::{AES128Cbc, BlockType};
use block_modes::BlockMode;
use block_modes::BlockModeError as Error;

type SwAES128Cbc = block_modes::Cbc<aes::Aes128, block_modes::block_padding::Pkcs7>;

pub struct SoftwareAES;

impl SoftwareAES {
    /// Does no work. Implemented to match interface with hardware implementations that required
    /// peripheral structs as arguments; can be omitted.
    pub fn new() -> Self {
        SoftwareAES {}
    }
}

impl AES128Cbc for SoftwareAES {
    type Error = Error;

    fn encrypt<'a>(
        &mut self,
        key: BlockType,
        iv: BlockType,
        buffer: &'a mut [u8],
        n: usize,
    ) -> Result<&'a [u8], Self::Error> {
        let cipher = SwAES128Cbc::new_var(&key, &iv).map_err(|_| Error)?;
        let buffer = cipher.encrypt(buffer, n)?;
        Ok(buffer)
    }

    fn decrypt<'a>(
        &mut self,
        key: BlockType,
        iv: BlockType,
        buffer: &'a mut [u8],
    ) -> Result<&'a [u8], Self::Error> {
        let cipher = SwAES128Cbc::new_var(&key, &iv).map_err(|_| Error)?;
        let buffer = cipher.decrypt(buffer)?;
        Ok(buffer)
    }
}
