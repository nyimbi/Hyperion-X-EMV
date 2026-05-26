# C ABI PoS Starter Kit

Start with `include/hyperion_emv.h` and the scripted C ABI adapter example:

```sh
cargo run --quiet --example krn_cabi_script_adapter
```

Production applications must provide bounded APDU, unpredictable-number, host, and PED callbacks and must verify all return codes.
