//! Example utilizing the hardware accelerated cryptography engine on the S32K144EVB-Q100
#![no_main]
#![no_std]

#[macro_use]
extern crate hex_literal;

extern crate panic_halt;

use cortex_m_rt::entry;
use s32k144;
use s32k144evb::wdog;

use eaesy_rtfm::{aes128cbc::AES128Cbc, s32k144::S32k144AES};

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

    let mut enctext = [0u8; 16];
    let mut dectext = [0u8; 16];

    let mut aes = S32k144AES::new(p.FTFC, p.CSE_PRAM);

    aes.encrypt(key, iv, &plaintext[..], &mut enctext).unwrap();
    aes.decrypt(key, iv, &enctext, &mut dectext).unwrap();

    assert!(&plaintext[..] == &dectext[..]);

    loop {}
}
