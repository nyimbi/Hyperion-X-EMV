# Certification Open-Issues Register

This register tracks certification blockers that are outside the
repository-controlled implementation and evidence set. It is not a defect list
for the Rust kernel. It is the controlled boundary between completed
pre-certification engineering work and evidence that must be supplied by
licensed standards review, schemes, acquirers, device vendors, security
assessors, or recognized laboratories.

Rows stay open until the referenced evidence is attached to the lab submission
pack and independently verified. Do not close an item based on passing unit
tests alone.

| ID | Area | Status | Blocking Evidence | Closure Criteria |
| --- | --- | --- | --- | --- |
| CERT-OPEN-001 | EMV Level 2 approval | Open | EMVCo/scheme laboratory execution, final test reports, signed approval or LoA | Signed approval artifacts cover every claimed interface, kernel, and scheme profile. |
| CERT-OPEN-002 | Scheme profile authority | Open | Lab/scheme/acquirer-signed AID, TAC/IAC, limit, CDA-control, and kernel-selection profile bundle | Bundled profiles are replaced or countersigned by accepted scheme/acquirer material and loaded through the signed-profile path. |
| CERT-OPEN-003 | CAPK authority | Open | Scheme/acquirer-approved CAPK set with signed provenance and checksum confirmation | CAPKs in the certification package trace to accepted public-key material and pass repository checksum/integrity gates. |
| CERT-OPEN-004 | ODA certification vectors | Open | Lab-supplied SDA, DDA, and CDA cryptographic vectors with expected outputs | `oda_test_vectors.json` is replaced by `vector_class = "CERTIFICATION"` data that passes complete-vector validation and lab review. |
| CERT-OPEN-005 | Contactless C-8 package | Open | C-8 approval package, lab profile data, test-tool results, and contactless outcome evidence | Contactless claims are backed by the unified kernel approval package and masked APDU/outcome traces for the accepted profile set. |
| CERT-OPEN-006 | Device and L1 evidence | Open | Target terminal, contact interface, contactless reader, and L1/device certification evidence | Target device and interface evidence matches the binary/profile set under submission. |
| CERT-OPEN-007 | PCI/PED security evidence | Open | PCI PTS POI integration statement, PED-owned VERIFY evidence, and device security review | PED integration evidence confirms opaque PIN handles, no clear PIN custody, and the certified device boundary. |
| CERT-OPEN-008 | Third-party security assessment | Open | Penetration test report covering APDU injection and state-machine bypass | External assessment accepts the APDU/state-bypass controls or tracks residual findings to closure. |
| CERT-OPEN-009 | Unit and integration reports | Open | Unit coverage report and full EMV test-plan integration report | Coverage and integration reports are attached and match the submitted binary, profiles, and annex hashes. |
| CERT-OPEN-010 | Static analysis and fuzzing | Open | Static-analysis report and fuzzing/no-crash report | Reports are attached, tool versions are recorded, and unresolved findings are accepted or remediated. |
| CERT-OPEN-011 | Signed conformance template | Open | Signed EMVCo/lab conformance statement template | Signed conformance template agrees with the ABI JSON statement, RTM, and claimed scope. |
| CERT-OPEN-012 | APDU trace pack | Open | Masked APDU traces for all applicable lab/test-tool cases | Trace pack is attached, replayable, masked, and tied to submitted profile/build identifiers. |
