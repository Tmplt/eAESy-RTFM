#![no_main]
#![no_std]

use cortex_m_rt::entry;
use s32k144;
use eaesy_rtfm::{self, AES128Cbc};

const MSG: &[u8] = b"Key:0123456789abKey:0123456789abKey:0123456789abKey:0123456789abKey:0123456789abKey:0123456789abKey:0123456789abKey:0123456789abKey:0123456789abKey:0123456789ab";
const MSG_LEN: usize = 16 * 10;
const IV: [u8; 16] = [0; 16];
const PLAINKEY: [u8; 16] = [
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
];

#[entry]
fn main() -> ! {
    let p = s32k144::Peripherals::take().unwrap();
    let mut aes = eaesy_rtfm::s32k144AES::new(p.FTFC, p.CSE_PRAM);

    let mut enctext: [u8; MSG_LEN] = [0; MSG_LEN];
    let mut dectext: [u8; MSG_LEN] = [0; MSG_LEN];

    aes.encrypt(PLAINKEY, IV, &MSG, &mut enctext).unwrap();
    aes.decrypt(PLAINKEY, IV, &enctext, &mut dectext).unwrap();

    assert!(&MSG[..] == &dectext[..]);

    loop {}
}
