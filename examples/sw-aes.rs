#![no_main]
#![no_std]

extern crate panic_semihosting;

#[macro_use] extern crate hex_literal;
extern crate aes_soft as aes;
// extern crate aes;
extern crate block_modes;

extern crate cortex_m;

use cortex_m_rt::entry;
// use eaesy_rtfm::{self, AES128Cbc};
use s32k144;
use s32k144evb::wdog;

use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use aes::Aes128;

// create an alias for convenience
type Aes128Cbc = Cbc<Aes128, Pkcs7>;

#[entry]
fn main() -> ! {
    // let p = s32k144::Peripherals::take().unwrap();

    // Disable watchdog
    // let wdog_settings = wdog::WatchdogSettings {
    //     enable: false,
    //     ..Default::default()
    // };
    // let _wdog = wdog::Watchdog::init(&p.WDOG, wdog_settings).unwrap();

    let key = hex!("000102030405060708090a0b0c0d0e0f");
    let iv = hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    let plaintext = b"Hello world!";
    let cipher = Aes128Cbc::new_var(&key, &iv).unwrap();

    // buffer must have enough space for message+padding
    let mut buffer = [0u8; 32];
    // copy message to the buffer
    let pos = plaintext.len();
    buffer[..pos].copy_from_slice(plaintext);
    let ciphertext = cipher.encrypt(&mut buffer, pos).unwrap();

    assert_eq!(ciphertext, hex!("1b7a4c403124ae2fb52bedc534d82fa8"));

    // re-create cipher mode instance
    let cipher = Aes128Cbc::new_var(&key, &iv).unwrap();
    let mut buffer = [0u8; 16];
    buffer[..].copy_from_slice(ciphertext);
    let decrypted_ciphertext = cipher.decrypt(&mut buffer).unwrap();

    assert_eq!(decrypted_ciphertext, plaintext);

    loop {
        cortex_m::asm::wfi();
    }
}
