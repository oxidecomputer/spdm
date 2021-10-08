This is a rust implementation of the [SPDM](https://www.dmtf.org/sites/default/files/standards/docu
ments/DSP0274_1.1.1.pdf) protocol specifically designed to work well with
microcontrollers and async networking in application level code. It is a `#[no_std]` codebase and
performs zero heap allocations. It also attempts to minimize the number of built in stack
allocations, deferring allocation of any memory to the user of this library.

The code follows the state machine of the SPDM protocol as closely as possible, and provides
safety to the user via the [typestate
pattern](https://cliffle.com/blog/rust-typestate/#continue-reading).

No transports are, or will be, implemented in this library. 
