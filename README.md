# zssh

Freestanding implementation of the ssh protocol. Not including implementations for cryptographic algorithms such as `ed25519`, or `sntrup761x25519-sha512`, etc... This allows for reuse of other established implementations, or use of non-spec defined algorithms. See: [using openssl] (TODO:) for more info.

Parsing of ssh primitives (i.e. keys, certkeys, sshsigs, agent messages) is done entirely in place.

The implementation is done in such way to allow for easy hacking of the protocol.

## Using:
> [!WARNING]
> Not ready for any type of use! Wait for 0.0.1 release.

TODO:

### Module:
TODO:

### As a lib:
TODO:

## Examples:
See [examples](examples/) for a comprehensive list of examples.

Running examples should be as easy as `zig build run -- <args>`, otherwise, see example specific README.

## Contributing:
Yes. No fuzz, just do it!

## Docs:
TODO:

## TODO:
See [TODO](TODO).

---
Happy hacking!!!
