//! Example comparing the two AES implementations for 16B input data
#![no_main]
#![no_std]

#[macro_use]
extern crate hex_literal;

extern crate panic_halt;

use cortex_m_rt::entry;
use s32k144;
use s32k144evb_hal::wdog;

use eaesy::{aes128cbc::AES128Cbc, default::SoftwareAES, s32k144::S32k144AES};

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
    let plaintext = b"Hello world!";

    let pos = plaintext.len();
    let mut sw_buffer = [0; 16];
    let mut hw_buffer = [0; 16];
    sw_buffer[..pos].copy_from_slice(plaintext);
    hw_buffer[..pos].copy_from_slice(plaintext);

    let mut sw_aes = SoftwareAES::new();
    let mut hw_aes = S32k144AES::new(p.FTFC, p.CSE_PRAM);

    // Encrypt data
    let sw_ciphertext = sw_aes.encrypt(key, iv, &mut sw_buffer, pos).unwrap();
    let hw_ciphertext = hw_aes.encrypt(key, iv, &mut hw_buffer, pos).unwrap();
    assert_eq!(sw_ciphertext, hw_ciphertext);

    // Decrypt data
    let sw_decrypted_ciphertext = sw_aes.decrypt(key, iv, &mut sw_buffer).unwrap();
    let hw_decrypted_ciphertext = hw_aes.decrypt(key, iv, &mut hw_buffer).unwrap();
    assert_eq!(sw_decrypted_ciphertext, hw_decrypted_ciphertext);
    assert_eq!(sw_decrypted_ciphertext, plaintext);

    loop {}
}
