e*AES*y — easy hardware-accelerated AES128CBC operations of arbitrary data on embedded targets
---

This crate exposes a trait for hardware-accelerated AES-128-CBC encryption/decryption on
`no-std` targets with available support. As a fallback, for targets that lack a cryptography
engine, a software implementation can be used instead. Arbitrary input lengths are supported
via PKCS7 padding.

At present, this crate utilizes the cryptography engines on the following targets:
- NXP S32K144EVB-Q100 (`s32k144evb-q100` feature)

License
---

Licensed under either of
* Apache License, Version 2.0 (LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license (LICENSE-MIT or http://opensource.org/licenses/MIT)

at your option.
