# Public Standards Watch

This annex records public standards and bulletin signals that affect the
pre-certification baseline. It is not a substitute for licensed EMVCo, scheme,
PCI, acquirer, device, or laboratory documents. Licensed materials and lab
instructions prevail on conflict.

## 2026-05-22 Public EMVCo Check

- Public source checked: EMVCo specifications and contactless technology pages.
- Contact baseline retained: EMV Contact Chip Specifications Book 3 v4.4, with
  Books 1, 2, and 4 where referenced by `docs/spec.md`.
- Contactless baseline in `docs/spec.md`: EMV Contactless Kernel Specification
  Book C-8 v1.0.
- Public drift to reconcile before any C-8 certification claim: EMVCo public
  materials list Book C-8 Kernel Specification v1.1 and SB 325, "Updates to
  Book C-8 v1.0", published 2026-05-07.
- Repository action: keep C-8 v1.0 as the current engineering target until
  licensed review, scheme profile data, lab test package selection, and target
  device evidence confirm whether the submission target must move to v1.1 or
  incorporate SB 325 behavior.

## Gating Rule

Do not close `CERT-OPEN-005` or claim final C-8 approval until the lab
submission package includes a licensed C-8 reconciliation note that states:

- the exact C-8 specification version and bulletin set used for testing;
- the approved test-tool package and version;
- any scheme/acquirer profile constraints that select or exclude C-8 v1.1 or
  SB 325 behavior; and
- the masked APDU/outcome traces for the accepted profile and device set.
