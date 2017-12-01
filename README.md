e*AES*y-RTFM — embedded AES {en,de}cryption
---
This project aims to implement AES support on a the NXP 43s50 microcontroller using Rust.
This project is a part of the D7018 course — *Special Studies in Embedded Systems*— taken at Luleå Technical University.

Instead of writing everything from scratch, rust-crypto will be used as base.
The following is what I want to accomplish:
1. write a Rust interface for the AES hardware;
2. extract and `nostd`-ify the AES component of rust-crypto (including test cases);
3. implement utilization of dedicated AES hardware on the microcontroller;
4. wrap with RTFM and utilize HW-component of microcontroller, and
5. (if time allows it) implement some secure communication protocol between host and microcontroller.

Docs, references
---
* [AES Wikipedia entry](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
* [rust-crypto](https://github.com/DaGenix/rust-crypto/tree/master/src)
* [microcontroller datasheet](https://www.nxp.com/docs/en/data-sheet/LPC43S50_30_20.pdf)

License
---
Licensed under either of
* Apache License, Version 2.0 (LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license (LICENSE-MIT or http://opensource.org/licenses/MIT)

at your option.

Contribution
---
I will not accept code contributions while the course is running. Bug reports are welcome, however.
