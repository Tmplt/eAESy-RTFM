e*AES*y-RTFM — embedded AES {en,de}cryption
---
This project aims to implement AES support on a the ??? microcontroller using Rust.
This project is a part of the D7018 course — *Special Studies in Embedded Systems*— taken at Luleå Technical University.

Instead of writing everything from scratch, rust-crypto will be used as base.
The following is what I want to accomplish:
1. extract and `nostd`-ify the AES component of rust-crypto (including test cases);
2. implement utilization of dedicated AES hardware on the microcontroller;
3. wrap with RTFM and utilize HW-component of microcontroller, and
4. (if time allows it) implement some secure communication protocol between host and microcontroller.

Docs, references
---
* [AES Wikipedia entry](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
* [rust-crypto](https://github.com/DaGenix/rust-crypto/tree/master/src)

...

License
---
Licensed under either of
* Apache License, Version 2.0 (LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license (LICENSE-MIT or http://opensource.org/licenses/MIT)

at your option.
