#![no_main]
#![no_std]

#[macro_use]
extern crate hex_literal;

extern crate cortex_m;
extern crate panic_halt;

use aes::Aes128;
use block_cipher_trait::generic_array::GenericArray;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use cortex_m_rt::entry;
use s32k144;
use s32k144evb::wdog;

// create an alias for convenience
type Aes128Cbc = Cbc<Aes128, Pkcs7>;

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

    // XXX: why do we hardfault when Aes128Cbc::new_var is used?
    let key_a = GenericArray::from_slice(&key);
    let iv_a = GenericArray::from_slice(&iv);
    let cipher = Aes128Cbc::new_fix(key_a, iv_a);

    // buffer must have enough space for message+padding
    let mut buffer = [0u8; 32];
    // // copy message to the buffer
    let pos = plaintext.len();
    buffer[..pos].copy_from_slice(plaintext);
    let ciphertext = cipher.encrypt(&mut buffer, pos).unwrap();

    assert_eq!(ciphertext, hex!("1b7a4c403124ae2fb52bedc534d82fa8"));

    // re-create cipher mode instance
    let cipher = Aes128Cbc::new_fix(key_a, iv_a);
    let mut buffer = [0u8; 16];
    buffer[..].copy_from_slice(ciphertext);
    let decrypted_ciphertext = cipher.decrypt(&mut buffer).unwrap();

    assert_eq!(decrypted_ciphertext, plaintext);

    loop {}
}
