# PC/SC Desktop Adapter Skeleton

The PC/SC adapter should stay outside the core kernel and map reader APDU exchange into the C ABI callback boundary.

Required production additions:

- Reader selection and card-present lifecycle.
- APDU timeout mapping to the active Hyperion callback timeout policy.
- Device/L1 identity capture for evidence packaging.
- Masked trace export for lab replay.
- Fail-closed handling for transport errors and malformed responses.
