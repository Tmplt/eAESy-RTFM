//! Trait exposing functions for encryption/decryption.

/// The size of a 128 bit block, in bytes, that is used as the atomic unit of work.
pub const BLOCK_SIZE: usize = 16;
/// Convenient alias for `[u8; 16]`, a 128 bit block which work is done on.
pub type BlockType = [u8; BLOCK_SIZE];

pub trait AES128Cbc {
    type Error;

    /// Pads input `buffer` via PKCS7 and returns a reference to `buffer` with padded data
    /// encrypted.
    fn encrypt<'a>(
        &mut self,
        key: BlockType,
        iv: BlockType,
        buffer: &'a mut [u8],
        n: usize,
    ) -> Result<&'a [u8], Self::Error>;

    /// Decrypts input `buffer` and unpads the data via PKCS7; returns a reference to `buffer`
    /// with unpadded data decrypted. Length of original data (`n` in `encrypt`) is derived from
    /// padding bytes.
    fn decrypt<'a>(
        &mut self,
        key: BlockType,
        iv: BlockType,
        buffer: &'a mut [u8],
    ) -> Result<&'a [u8], Self::Error>;
}
