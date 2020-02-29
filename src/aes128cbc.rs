pub trait AES128Cbc {
    type Error;

    fn encrypt<'a>(
        &mut self,
        key: [u8; 16],
        iv: [u8; 16],
        buffer: &'a mut [u8],
        n: usize,
    ) -> Result<&'a [u8], Self::Error>;

    fn decrypt<'a>(
        &mut self,
        key: [u8; 16],
        iv: [u8; 16],
        buffer: &'a mut [u8],
    ) -> Result<&'a [u8], Self::Error>;
}
