# zssh

Freestanding implementation of the ssh protocol. Not including implementations for "non-ssh" cryptographic algorithms such as `ed25519` or `sntrup761x25519-sha512`, this allows for reuse of other established implementations, or use of non-spec defined algorithms. Only `bcrypt` and alike are included. But, can be overwritten, see: [using openssl] (TODO:) for more info.

Parsing of ssh primitives (key, certkeys, and sshsig) is done entirely in place.

The implementation is done in such way to allow for easy hacking of the protocol, i.e., new key types, algorithms, or agent extensions.


## Using:
> [!WARNING]
> Not ready for any type of use! Wait for 0.0.1 release.

TODO:

### Module:
TODO:

### As a lib:
TODO:

## Examples:
TODO:

## Docs:
TODO:

## TODO:
See TODO for a list of what is left to do.
