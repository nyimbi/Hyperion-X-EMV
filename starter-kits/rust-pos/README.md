# Rust PoS Starter Kit

Use the Rust API for rapid terminal integration experiments before freezing a C ABI or device adapter boundary.

```sh
cargo run --quiet --example krn_basic_pos
```

Replace fixture APDU callbacks with a real reader transport, load a signed data bundle, and keep PAN/track data out of logs.
