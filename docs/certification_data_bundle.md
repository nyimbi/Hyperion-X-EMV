# Hyperion Data-Driven Certification Bundle

- Bundle ID: `hyperion-c8-contact-certification-fixture`
- Bundle class: `CERTIFICATION`
- Rollback counter: `2`
- Verification status: `trust-anchor-verified`
- Payload SHA-256: `5d0e03b2dc65006c22a88bfefa1a1d16d65713650dabc92445d397b4be911ebd`
- Bundle SHA-256: `c13ea7cb3a99d11b0228fad4af0855ce8b29359e3614de99761a399899ed9e2b`
- Scheme profile SHA-256: `8d67a1fc92061dfbfea39ebabc30ddd744998e7fe18789570c32a7b20b9d630f`
- Vector bundle SHA-256: `17e599c785c424433baf0e01fe13bb633cbb426217a474181d0083a1d6bd0515`

## Data-Driven Scope

- Product: `Hyperion EMV Kernel` `0.1.0`
- Target: `contact-and-c8-contactless-prelab`
- Interfaces: `contact, contactless`
- Kernel registry entries: `1`
- Test-plan cases: `1`
- Artifact bindings: `2`

Boundary: the same Rust binary can load a different certification bundle without source changes, provided the bundle verifies against configured trust-anchor data. External lab, scheme, device, PCI/PED, CAPK, vector, and approval evidence remains authoritative.
