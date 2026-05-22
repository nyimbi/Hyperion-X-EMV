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
- Public C-8 drift to reconcile before any C-8 certification claim: EMVCo
  public materials list Book C-8 Kernel Specification v1.1 and SB 325,
  "Updates to Book C-8 v1.0", published 2026-05-07.
- Public contactless-suite drift to track with the licensed review: EMVCo
  public materials list SB 326, "Updates to Book A", SB 327, "Updates to Book
  B", and DSB 331, "RRP Requirements for Kernel 2", all published
  2026-05-21. These are not repository-controlled implementation authority,
  but they are current public signals that the lab-selected contactless
  version, bulletin set, and scheme acceptance package must explicitly accept,
  exclude, or defer.
- Public adjacent bulletin signals to keep out of direct code changes until the
  licensed/lab package selects them: EMVCo public materials list SB 314,
  "Update to TRMD", published 2026-05-07; DSB 324, "Updates to C-4", published
  2026-04-16 with a 2026-05-22 comment period; and DSB 308, "Contact Features
  Sunsetting P1", published 2026-03-31 with a 2026-05-01 comment-period end.
  These items are watch-list inputs for profile selection, contact/contactless
  scope control, and lab reconciliation. They do not authorize Hyperion to infer
  unlicensed TRMD, C-4, or contact-feature behavior.
- Repository action: keep C-8 v1.0 as the current engineering target until
  licensed review, scheme profile data, lab test package selection, and target
  device evidence confirm whether the submission target must move to v1.1 or
  incorporate SB 325 behavior. Treat SB 326, SB 327, and DSB 331 as
  contactless-suite reconciliation inputs, and treat SB 314, DSB 324, and
  DSB 308 as adjacent watch-list inputs, not as direct Hyperion code changes,
  unless the licensed profile/lab package selects their behavior for the
  submitted binary.

## 2026-05-22 Public Approval-Process Check

- Public source checked: EMVCo specifications, contactless technology,
  contactless product approval process, contact kernel approval process, and
  Contactless Kernel 8 testing announcement pages.
- Contactless approval signal: EMVCo public materials state that the
  Contactless Product approval process covers a Contactless acceptance device
  or a Contactless Kernel C-8, and attests compliance with the EMV
  specification.
- Contactless Kernel 8 process signal: EMVCo states that Contactless Kernel 8
  approval can be pursued as one element of a full contactless acceptance
  device, as a standalone kernel, or as a delta after integrating an already
  approved kernel into another device.
- Contactless Kernel 8 evidence signal: EMVCo public process material lists
  different implementation conformance statement paths for full device,
  standalone kernel, and approved-kernel integration submissions; the repository
  therefore treats the lab-selected ICS path as external evidence.
- Approval artifact signal: EMVCo public process material describes EMVCo
  review of laboratory test reports and issuance of a Letter of Approval when
  sufficient conformance is demonstrated. Do not replace this with repository
  ABI JSON or pre-lab trace fixtures.

## 2026-05-22 Public PCI PTS / PED Check

- Public source checked: PCI SSC PTS POI standards, PCI SSC document library,
  PCI SSC PTS POI v7.0 publication note, and PCI SSC approved PTS device
  listing.
- PCI baseline retained: PCI PIN Transaction Security (PTS) Point of
  Interaction (POI) Modular Security Requirements v7.0 as the public alignment
  target for PED and secure PIN-entry integration.
- Public PCI signal: PCI SSC describes PTS POI as requirements for devices that
  protect PINs, account data, and other sensitive payment data at the point of
  interaction; PCI-recognized laboratories validate approved PTS devices and
  PCI SSC publishes approved-device listings.
- Repository action: keep Hyperion's kernel boundary limited to opaque PED
  handles, VERIFY status, and no clear-PIN custody. Do not claim PCI PTS
  alignment or close `CERT-OPEN-007` until the target POI/PED integration
  statement, device approval listing, and security review are attached to the
  lab/acquirer package.

## Gating Rule

Do not close `CERT-OPEN-005` or claim final C-8 approval until the lab
submission package includes a licensed C-8 reconciliation note that states:

- the exact C-8 specification version and bulletin set used for testing;
- the exact Contactless Kernel 8 approval path used: full device, standalone
  kernel, or approved-kernel integration delta;
- the Contactless Kernel 8 implementation conformance statement form(s) and
  versions accepted by the laboratory;
- the approved test-tool package and version;
- any scheme/acquirer profile constraints that select or exclude C-8 v1.1 or
  SB 325 behavior;
- any common contactless Book A/Book B bulletin constraints, including SB 326
  and SB 327, that affect the target device or entry-point evidence;
- any Kernel 2 relay-resistance or RRP constraints, including DSB 331, that are
  accepted, excluded, or declared out of scope for the claimed C-8 package; and
- any adjacent contactless TRMD, C-4, or contact-feature bulletin constraints,
  including SB 314, DSB 324, and DSB 308, that the lab or scheme requires for
  the target device, profile set, or claimed contact/contactless scope; and
- the laboratory test reports and Letter of Approval or equivalent scheme/lab
  approval artifact;
- the masked APDU/outcome traces for the accepted profile and device set.

Do not close `CERT-OPEN-007` or claim PCI PTS POI alignment until the lab or
acquirer package includes:

- the exact PCI PTS POI requirements version accepted for the target product;
- the target device or PED approval listing/reference;
- the PED integration statement covering offline PIN VERIFY status, online PIN
  block custody, secure handles, and no clear-PIN kernel memory;
- device security review evidence for tamper and point-of-interaction
  controls; and
- any acquirer or scheme acceptance notes tying the approved device/PED boundary
  to the submitted Hyperion binary and profile set.
