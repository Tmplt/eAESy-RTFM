//! Example comparing the two AES implementations for 16B input data
#![no_main]
#![no_std]

#[macro_use]
extern crate hex_literal;

extern crate panic_halt;

use aes::Aes128;
use block_cipher_trait::generic_array::GenericArray;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use cortex_m_rt::entry;
use eaesy_rtfm::{self, AES128Cbc};
use s32k144;
use s32k144evb::wdog;

// create an alias for convenience
type Aes128CbcSw = Cbc<Aes128, Pkcs7>;

#[entry]
fn main() -> ! {
    let p = s32k144::Peripherals::take().unwrap();

    // Disable watchdog
    let wdog_settings = wdog::WatchdogSettings {
        enable: false,
        ..Default::default()
    };
    let _wdog = wdog::Watchdog::init(&p.WDOG, wdog_settings).unwrap();

    let key = hex!("000102030405060708090a0b0c0d0e0f");
    let iv = hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    let plaintext = b"Hello world!\0\0\0\0"; // pad for 16B length

    let mut hw_ciphertext: [u8; 16] = [0; 16];
    let mut hw_decrypted_ciphertext = [0u8; 16];
    let mut sw_buffer = [0u8; 32];

    // Encrypt via hardware
    let mut aes = eaesy_rtfm::s32k144AES::new(p.FTFC, p.CSE_PRAM);
    aes.encrypt(key, iv, &plaintext[..], &mut hw_ciphertext)
        .unwrap();

    // Encrypt via software
    let key_a = GenericArray::from_slice(&key);
    let iv_a = GenericArray::from_slice(&iv);
    let cipher = Aes128CbcSw::new_fix(key_a, iv_a);
    let pos = plaintext.len();
    sw_buffer[..pos].copy_from_slice(plaintext);
    let sw_ciphertext = cipher.encrypt(&mut sw_buffer, pos).unwrap();

    // Ensure generated cipher matches between the implementations
    assert_eq!(sw_ciphertext[..pos], hw_ciphertext);

    // Decrypt via hardware
    aes.decrypt(key, iv, &hw_ciphertext, &mut hw_decrypted_ciphertext)
        .unwrap();

    // Decrypt via software
    let cipher = Aes128CbcSw::new_fix(key_a, iv_a);
    let sw_decrypted_ciphertext = cipher.decrypt(&mut sw_buffer).unwrap();

    // Ensure decrypted data matches between the implementations
    assert_eq!(sw_decrypted_ciphertext[..pos], hw_decrypted_ciphertext);
    assert_eq!(plaintext[..], sw_decrypted_ciphertext[..pos]);

    loop {}
}
