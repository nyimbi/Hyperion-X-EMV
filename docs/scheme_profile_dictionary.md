# Scheme Profile Dictionary

Generated from `docs/scheme_profiles.cert.json` by `cargo run --example krn_scheme_profile_dictionary`.

This is a repository-controlled review aid. It does not replace lab, scheme, acquirer, or CAPK authority evidence and does not close `CERT-OPEN-002` or `CERT-OPEN-003`.

## Bundle Scope

- Version: 2
- Profile class: CERTIFICATION
- Source owner: Hyperion-X Certification
- Source document: signed_certification_profile_bundle
- Source verification: external_signature_required
- Source retrieved: 2026-05-21
- Scheme count: 2

## Visa

- RID: A000000003
- Contactless kernel profile: c8_contactless
- Contact kernel profile: legacy_visa
- TAA fallback when unable online: AAC
- TAA no-match default when online capable: ARQC
- TAA no-match default when offline only: AAC

### AID Profiles

#### AID `A0000000031010`

- Priority: 10
- Partial selection: true
- Interfaces: contact, contactless
- Terminal capabilities: 9F33 is supplied through the ABI, not embedded in this profile
- TTQ: 9F66 is supplied through the ABI for contactless DOL data, not embedded in this profile
- Floor limit: 0
- Contact CVM limit: 5000
- Contactless transaction limit: 5000
- Contactless CVM limit: 3000
- Random selection percent: 5
- CDCVM supported: true
- CDA supported: true
- CDA request encoding: CDOL1 bit
- Default CDOL1 length: 18 bytes
- Critical issuer script INS: E2
- TAC: denial=0000000000, online=E0F8C80000, default=8000000000
- IAC: denial=0000000000, online=0000000000, default=0000000000

### CAPK Provenance

- RID: A000000003
  - Key index: 9
  - Modulus length: 248 bytes
  - Exponent length: 1 bytes
  - Expiry: 2031-12-31
  - Checksum: 1FF80A40173F52D7D27E0F26A146A1C8CCB29046
  - Source owner: Visa
  - Source document: signed_certification_capk_bundle
  - Source verification: external_signature_required
  - Source retrieved: 2026-05-21

## Mastercard

- RID: A000000004
- Contactless kernel profile: c8_contactless
- Contact kernel profile: legacy_mastercard
- TAA fallback when unable online: AAC
- TAA no-match default when online capable: ARQC
- TAA no-match default when offline only: AAC

### AID Profiles

#### AID `A0000000041010`

- Priority: 10
- Partial selection: false
- Interfaces: contact, contactless
- Terminal capabilities: 9F33 is supplied through the ABI, not embedded in this profile
- TTQ: 9F66 is supplied through the ABI for contactless DOL data, not embedded in this profile
- Floor limit: 0
- Contact CVM limit: 10000
- Contactless transaction limit: 10000
- Contactless CVM limit: 5000
- Random selection percent: 10
- CDCVM supported: true
- CDA supported: true
- CDA request encoding: P1 low bits 0x10
- Default CDOL1 length: 18 bytes
- Critical issuer script INS: E2
- TAC: denial=0F00000000, online=F0F8C80000, default=8000000000
- IAC: denial=0000000000, online=0000000000, default=0000000000

### CAPK Provenance

- RID: A000000004
  - Key index: 6
  - Modulus length: 248 bytes
  - Exponent length: 1 bytes
  - Expiry: 2028-12-31
  - Checksum: F910A1504D5FFB793D94F3B500765E1ABCAD72D9
  - Source owner: Mastercard
  - Source document: signed_certification_capk_bundle
  - Source verification: external_signature_required
  - Source retrieved: 2026-05-21
