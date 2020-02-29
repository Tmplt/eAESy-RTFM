use crate::aes128cbc::{AES128Cbc, BlockType, BLOCK_SIZE};

use block_padding::{Padding, Pkcs7};
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
}

impl AES128Cbc for S32k144AES {
    type Error = Error;

    fn encrypt<'a>(
        &mut self,
        key: BlockType,
        iv: BlockType,
        buffer: &'a mut [u8],
        n: usize,
    ) -> Result<&'a [u8], Error> {
        // Pad upwards to the first 16B multiple
        fn round_up_block(n: usize) -> usize {
            ((n / BLOCK_SIZE) + (if n % 16 != 0 { 1 } else { 0 })) * 16
        }
        let buffer = Pkcs7::pad(buffer, n, round_up_block(n)).map_err(|_| Error::GeneralError)?;
        assert!(buffer.len() % 16 == 0);

        // Encrypt in-place
        self.csec.load_plainkey(&key)?;
        // XXX: will fail if buffer is more than u16::max_value() * 16 bytes in length (hardware
        // limitation).
        self.csec.encrypt_cbc(&iv, buffer)?;

        Ok(buffer)
    }

    fn decrypt<'a>(
        &mut self,
        key: BlockType,
        iv: BlockType,
        buffer: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        if buffer.len() % 16 != 0 {
            return Err(Error::GeneralError);
        }

        // Decrypt in-place
        self.csec.load_plainkey(&key)?;
        // XXX: will fail if buffer is more than u16::max_value() * 16 bytes in length (hardware
        // limitation).
        self.csec.decrypt_cbc(&iv, buffer)?;

        // Remove padding. Length of encryption input is derived from padding.
        let buffer = Pkcs7::unpad(buffer).map_err(|_| Error::GeneralError)?;
        Ok(buffer)
    }
}
