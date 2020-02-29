use crate::aes128cbc::{AES128Cbc, BlockType, BLOCK_SIZE};

use block_padding::{Padding, Pkcs7};
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

        // Encrypt in-place
        // TODO: use all available pages here
        for chunk in buffer.chunks_mut(16) {
            self.csec.load_plainkey(&key)?;
            self.csec.encrypt_cbc(&iv, chunk.try_into().unwrap())?;
        }
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
        // TODO: use all available pages
        for chunk in buffer.chunks_mut(16) {
            self.csec.load_plainkey(&key)?;
            self.csec.decrypt_cbc(&iv, chunk.try_into().unwrap())?;
        }

        // Remove padding
        let buffer = Pkcs7::unpad(buffer).map_err(|_| Error::GeneralError)?;
        Ok(buffer)
    }
}
