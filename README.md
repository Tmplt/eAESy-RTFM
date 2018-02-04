e*AES*y-RTFM — embedded AES {en,de}cryption
---

This project aims to implement AES support on the NXP LPC4357 micro controller (with a LPC43s50 MCU) using Rust.
This project is a part of the D7018 course — *Special Studies in Embedded Systems* — taken at Luleå Technical University.

Instead of writing everything from scratch, rust-crypto will be used as base.
This project is divided into several parts I want to accomplish:
1. get a grasp of the AES hardware and write a Rust interface for it.
2. extract and `nostd`-ify the AES component of rust-crypto (including test cases);
3. implement utilization of dedicated AES hardware on the microcontroller;
4. Abstract the API so that it may work with the Nucleo as well.
5. wrap everything up with RTFM, and
6. (if time allows it) implement some secure communication protocol between host and microcontroller.

**Project status**:
- [x] acquire AES API documentation
- [x] acquire AES API code examples (see `playground` branch)
- [ ] fully understand the above (i.e. utilize examples, program hardware with it)
- [ ] port headers to Rust
- [ ] port AES API to Rust

Grading
---

3. Experiment with the LPC43s50 micro controller and backport the AES component of Rust's crypto crate to run on the micro controller. Build a demo that securely communicates secrets with a host system using AES.

4. Design a proper implementation of an API that would allow the crate to compile and run on both the LPC43s50 and the STM32F042K6 (with an appropriate AES-supporting MCU) microcontrollers with minimal alterations.

5. Implement the API with proper documentation, testing and examples. Show a proof of correctness by writing test cases and/or examples.

Docs, references
---

* [AES Wikipedia entry](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
* [rust-crypto](https://github.com/DaGenix/rust-crypto/tree/master/src)
* [microcontroller datasheet](https://github.com/Tmplt/eAESy-RTFM/blob/master/doc/LPC43S50/Datasheet.pdf)
* [microcontroller users guide](https://github.com/Tmplt/eAESy-RTFM/blob/master/doc/LPC43S50/Users%20Guide.pdf) — contains AES API documentation, function table offsets.
* [Rust bindings for LPC43SXX](https://gitlab.henriktjader.com/pln/LPC43xx_43Sxx) — and [documentation for it](http://pln.gitpages.henriktjader.com/LPC43xx_43Sxx/lpc43xx_43sxx/) (possibly incomplete for AES engine usage)

License
---

Licensed under either of
* Apache License, Version 2.0 (LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license (LICENSE-MIT or http://opensource.org/licenses/MIT)

at your option.

Contribution
---

I will not accept code contributions while the course is running (until this notice is removed).
Bug reports are welcome, however.
