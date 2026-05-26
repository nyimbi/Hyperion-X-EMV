# Android SoftPoS Adapter Skeleton

The Android adapter should keep NFC, CDCVM, device attestation, and mobile acceptance approval outside the core kernel. Use JNI or a Rust mobile bridge to call the C ABI, then map Android NFC transceive operations into `KrnTransmitApduCallback`.

Required production additions:

- Android NFC reader lifecycle and timeout mapping.
- Device attestation and app integrity evidence export.
- CDCVM/mobile acceptance evidence capture.
- Secure storage for signed bundle and trust anchors.
- No clear PAN, track, PIN, or private signing key logging.
