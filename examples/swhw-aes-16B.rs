//! Example comparing the two AES implementations for 16B input data
#![no_main]
#![no_std]

#[macro_use]
extern crate hex_literal;

extern crate panic_halt;

use cortex_m_rt::entry;
use s32k144;
use s32k144evb::wdog;

use eaesy_rtfm::{aes128cbc::AES128Cbc, default::SoftwareAES, s32k144::S32k144AES};

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
    let pos = plaintext.len();

    let mut hw_ciphertext = [0; 16];
    let mut hw_decrypted_ciphertext = [0u8; 16];
    let mut sw_ciphertext = [0u8; 32];
    let mut sw_decrypted_ciphertext = [0u8; 32];

    // Encrypt via hardware
    let mut hw_aes = S32k144AES::new(p.FTFC, p.CSE_PRAM);
    hw_aes
        .encrypt(key, iv, &plaintext[..], &mut hw_ciphertext)
        .unwrap();

    // Encrypt via software
    let mut sw_aes = SoftwareAES::new();
    sw_aes
        .encrypt(key, iv, &plaintext[..], &mut sw_ciphertext)
        .unwrap();

    // Ensure generated cipher matches between the implementations
    assert_eq!(sw_ciphertext[..pos], hw_ciphertext);

    // Decrypt via hardware
    hw_aes
        .decrypt(key, iv, &hw_ciphertext, &mut hw_decrypted_ciphertext)
        .unwrap();

    // Decrypt via software
    sw_aes
        .decrypt(key, iv, &sw_ciphertext, &mut sw_decrypted_ciphertext)
        .unwrap();

    // Ensure decrypted data matches between the implementations
    assert_eq!(sw_decrypted_ciphertext[..pos], hw_decrypted_ciphertext);
    assert_eq!(plaintext[..], sw_decrypted_ciphertext[..pos]);

    loop {}
}
