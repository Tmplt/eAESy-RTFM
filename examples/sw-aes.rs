//! Example of the fallback implemenation of AES128CBC
#![no_main]
#![no_std]

#[macro_use]
extern crate hex_literal;

extern crate panic_halt;

use cortex_m_rt::entry;
use s32k144;
use s32k144evb::wdog;

use eaesy::{aes128cbc::AES128Cbc, default::SoftwareAES};

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
    let mut buffer = [0; 16];
    buffer[..pos].copy_from_slice(plaintext);

    let mut aes = SoftwareAES::new();

    let _ciphertext = aes.encrypt(key, iv, &mut buffer, pos).unwrap();
    let decrypted_ciphertext = aes.decrypt(key, iv, &mut buffer).unwrap();

    assert_eq!(plaintext, decrypted_ciphertext);

    loop {}
}
