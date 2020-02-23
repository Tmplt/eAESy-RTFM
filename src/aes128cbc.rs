pub trait AES128Cbc {
    type Error;

    fn encrypt(
        &mut self,
        key: [u8; 16],
        iv: [u8; 16],
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<(), Self::Error>;

    fn decrypt(
        &mut self,
        key: [u8; 16],
        iv: [u8; 16],
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<(), Self::Error>;
}
