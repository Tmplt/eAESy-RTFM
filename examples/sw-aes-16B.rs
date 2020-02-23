//! Example of the fallback implemenation of AES128CBC
#![no_main]
#![no_std]

#[macro_use]
extern crate hex_literal;

extern crate panic_halt;

use cortex_m_rt::entry;
use s32k144;
use s32k144evb::wdog;

use eaesy_rtfm::{aes128cbc::AES128Cbc, default::SoftwareAES};

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

    // XXX: padding must be larger than `plaintext` here.
    let mut enctext = [0u8; 32];
    let mut dectext = [0u8; 32];

    let mut aes = SoftwareAES::new();

    aes.encrypt(key, iv, &plaintext[..], &mut enctext).unwrap();
    aes.decrypt(key, iv, &enctext, &mut dectext).unwrap();

    // NOTE(..16): ad-hoc b/c buffers are 32 instead of 16.
    assert!(&plaintext[..16] == &dectext[..16]);

    loop {}
}
