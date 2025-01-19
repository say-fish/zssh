# zssh

Freestanding implementation of the ssh protocol. Not including implementations for "non-ssh" cryptographic algorithms such as `ed25519` or `sntrup761x25519-sha512`, this allows for reuse of other established implementations, or use of non-spec defined algorithms. Only `bcrypt` and other common encryption algorithms are included, but can be overwritten, see: [using openssl] (TODO:) for more info.

Parsing of ssh primitives (key, certkeys, and sshsig) is done entirely in place.

## Using:
TODO;

### Module:
TODO:

### As a lib:
TODO:

## Examples:
TODO:

## Docs:
TODO:
