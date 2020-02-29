pub const BLOCK_SIZE: usize = 16;
pub type BlockType = [u8; BLOCK_SIZE];

pub trait AES128Cbc {
    type Error;

    fn encrypt<'a>(
        &mut self,
        key: BlockType,
        iv: BlockType,
        buffer: &'a mut [u8],
        n: usize,
    ) -> Result<&'a [u8], Self::Error>;

    fn decrypt<'a>(
        &mut self,
        key: BlockType,
        iv: BlockType,
        buffer: &'a mut [u8],
    ) -> Result<&'a [u8], Self::Error>;
}
