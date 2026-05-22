# Open-Source EMV Reference Review

This review records implementation ideas from adjacent EMV projects that
Hyperion can adapt without copying source code, constants, private test data, or
scheme behavior. The repositories were inspected as learning material only.
Hyperion remains a clean-room Rust kernel governed by `docs/spec.md`,
`docs/eng_notes.md`, signed profile inputs, licensed EMVCo/scheme material, and
lab evidence.

Review date: 2026-05-23.

Temporary clone roots inspected under
`/private/tmp/hyperion-reference-review-20260523`:

| Project | Inspected revision or source | License posture observed | Review stance |
| --- | --- | --- | --- |
| `vicente-da-silva/dcemv` | `7a8ee22e434563af0703b05a679e04a1cc44e55f` | `LICENSE` is AGPL-3.0 | Architecture and playground ideas only; avoid source/code reuse. |
| `greenboxal/emv-kernel` | `dbbe8cc2f606ad17c40f09060fd427961bef2842` | README states MIT; no root license file observed | Educational flow ideas only; code is proof-of-concept and incomplete. |
| `MohamedHassanNasr/emv` | `cfa823a25e9fac6a5b42c99e1b8a7297b88848dd` | Header notices use permissive BSD-style terms; no root license file observed | Contactless architecture and integration ideas only. |
| `mrautio/emvpt` | `e9ee8894ac250457914d80d5bd1c7f261023331d` | zlib-style license in `LICENSE` | Rust harness/test ideas are useful; do not treat as L2 foundation. |
| `openemv/emv-utils` | `661bf635caa340c063fdcfce45896c02e5dce521` | LGPL-2.1-or-later | Tooling and validation concepts only unless legal review approves linkage. |
| `emerald79/libpay` | `18580a3d3ccbd68e1f443b756e7f0d8da29308ba` | LGPL-3.0-or-later | Entry-point/configuration ideas only; avoid direct reuse. |
| Switstack Moka | Public product/docs pages only | Source available after onboarding/evaluation access; no public Moka source tree observed | Process benchmark only; source review requires controlled source access. |

## Cross-Project Takeaways

The strongest reusable ideas are not algorithm snippets. They are process and
test structures:

1. Keep the certified kernel small and deterministic, with platform/device
   bindings outside the core.
2. Build standalone APDU/TLV/DOL tooling that can decode, mask, replay, and
   compare lab traces without invoking the full terminal app.
3. Make transaction evidence fixture-driven: request/response scripts, terminal
   config, expected state transitions, and expected output artifacts should be
   checked into reproducible annexes.
4. Treat reader/L1/terminal integrations as callbacks or message queues, so the
   same kernel can run against PC/SC, mocks, mobile NFC, or lab tools.
5. Keep open-source references out of the certification chain. Their tests can
   inspire repository-controlled pre-lab evidence, but they do not replace
   licensed specifications, scheme bulletins, CAPKs, lab vectors, or approval
   reports.

## Project Notes

### dcemv

Inspected files and areas:

- `README.MD`
- `LICENSE`
- `DCEMV_EMVProtocol/StateEngine/StateEngine.cs`
- `DCEMV_EMVProtocol/EMVCard/KernelShared/Q/KernelRequestResponse.cs`
- `DCEMV_EMVProtocol/EMVCard/KernelShared/KernelDatabaseBase.cs`
- `DCEMV_EMVProtocol/EMVCard/KernelShared/Instructions/EMVGenerateAC.cs`
- `DCEMV_TLVProtocol/TLV.cs`
- `DCEMV_TLVProtocol/TLVList.cs`
- `DCEMV_EMVProtocol/EMVCard/Terminal/*`
- reader driver projects for Android, Windows PC/SC, Bluetooth ACS1255, NCI,
  Raspberry Pi/OM5577, and virtual card emulation.

Useful ideas to adapt:

- Full-stack playground layout: protocol core, terminal app, UI, card emulator,
  reader drivers, simulated issuer/acquirer, and demo server are separated into
  distinct projects. Hyperion can mirror this at a smaller scale with a
  repository-controlled simulator package and reader adapters outside `src`.
- Kernel-terminal queue boundary: `KernelRequestResponse.cs` models terminal
  requests and kernel responses for UI, PIN, TRM, online authorization, and
  final outcome. Hyperion already has a C ABI and callback boundary; this
  suggests documenting every callback as a typed service request with explicit
  data-custody rules.
- Kernel database with tag update policy: `KernelDatabaseBase.cs` centralizes
  response parsing, TLV storage, update permissions, and ODA data assembly.
  Hyperion already has typed modules; the borrowable pattern is an explicit
  "card-originated tag admission" audit table in the RTM.
- Pre-certification ambition is honest: the README distinguishes playground
  usage from hardware/lab certification. Hyperion should keep the same boundary
  prominent in `docs/certification_open_issues.md`.

Do not borrow:

- AGPL source text or implementation structure.
- Demo server, UI, or simulated issuer behavior as certification evidence.
- Verbose APDU logging patterns that expose CDOL, cryptogram, PAN, or PIN data.

### greenboxal/emv-kernel

Inspected files and areas:

- `readme.md`
- `transactionprocessor.go`
- `emv/context.go`
- `emv/card.go`
- `emv/dataobjectlist.go`
- `emv/generatedac.go`
- `emv/contextconfig.go`
- `tlv/tlv.go`
- `filecertificatemanager.go`
- `certs/*`

Useful ideas to adapt:

- A short, readable end-to-end transaction path is valuable for smoke tests:
  initialize card, list/select application, select app, GPO, read AFL records,
  authenticate, and later generate AC. Hyperion can maintain a compact
  "happy-path transaction script" example alongside deeper module tests.
- The APDU wrapper automatically handles `61xx` GET RESPONSE and `6Cxx` retry
  status. Hyperion recently added similar replay handling; the remaining useful
  pattern is to keep those follow-up cases visible in trace fixtures.
- `buildDol` illustrates a source-priority problem: DOL values may come from
  transaction params, terminal config, ICC data, or generated randomness.
  Hyperion should document DOL source precedence in one place and keep tests for
  missing/short/long values.
- The file certificate manager is too simple for production, but the directory
  shape `RID/index` is a useful test fixture convention for CAPK provenance
  tests.

Do not borrow:

- The README itself says not to expect production or certification readiness.
- Clear PIN entry and direct VERIFY construction are unsuitable for Hyperion's
  PED-owned PIN boundary.
- In-repo public-key material should not become Hyperion certification CAPKs.
- Reflection/map-based TLV mutation is not a good fit for Hyperion's bounded,
  redacted, typed Rust model.

### MohamedHassanNasr/emv

Inspected files and areas:

- `README.md`
- `emv.h`
- `contactless_k2.h`
- `contactless_k3.h`
- `config_parser.h`
- `message_and_id.h`
- `mock/mock.h`
- `mock/*.json`
- `cfg/*.json`
- `native/main.cpp`
- `native/os_linux.h`
- `secure_allocator.h`

Useful ideas to adapt:

- Message-router architecture: the README describes L1, L2, and L3 separation
  through generic queues, with options for local, IPC, UDP, or Android NFC
  routing. Hyperion can adapt this as a formal adapter contract around the C ABI
  and trace pack.
- Runtime configuration layering: multiple config files can inherit and
  override one another, with command-line selection. Hyperion has signed
  profiles; the useful adaptation is deterministic profile overlay tests for
  lab, acquirer, and device-specific overrides.
- Mock-first integration: `mock/*.json` and `mock.h` give complete transaction
  flows independent of a real NFC reader. Hyperion should extend
  `docs/prelab_apdu_trace_pack.jsonl` into a broader script pack with expected
  outcomes and state transitions.
- K2/K3 state code records contactless-specific validation concerns, including
  duplicate card tags, PAN/track consistency, AFL ODA data assembly, TTQ, and
  relay-resistance inputs. Hyperion should use those topics as a checklist, not
  as source logic.

Do not borrow:

- The README explicitly says many mandatory features are missing and the code is
  not certified.
- Header-only code shape is convenient for demos but not appropriate for a
  certification-maintained Rust kernel.
- Networked mock routing must not weaken sensitive-data custody or trace
  masking.

### mrautio/emvpt

Inspected files and areas:

- `README.md`
- `LICENSE`
- `emvpt/Cargo.toml`
- `emvpt/src/lib.rs`
- `emvpt/src/bcdutil/mod.rs`
- `emvpt/src/config/*.yaml`
- `emvpt/test_data.yaml`
- `terminalsimulator/src/main.rs`

Useful ideas to adapt:

- The `ApduInterface` trait plus a PC/SC terminal simulator is the most directly
  relevant pattern for Hyperion. Hyperion can add a small crate/example that
  drives the existing kernel through a mock/PCSC adapter without putting PC/SC
  inside the core.
- The library tests use a `DummySmartCardConnection` backed by YAML
  request/response data. Hyperion should continue expanding deterministic
  JSONL/YAML APDU scripts with expected terminal outcomes.
- The simulator exposes useful debug modes: stop after connect, stop after read,
  print TLV, print tags, and censor sensitive fields. Hyperion's examples can
  adopt those command-shape ideas while keeping default output masked.
- Tests cover PAN truncation, track parsing/censoring, BCD conversion, DOL
  construction, PIN verification APDUs, and purchase flow. Hyperion already has
  stronger separation around PIN custody; the borrowable part is fixture-driven
  validation of redaction and BCD/track edge cases.

Do not borrow:

- The README scopes the project to simple EMV transaction cases; it is not a
  complete L2 kernel.
- The dependency set and single large `lib.rs` are not a pattern to import.
- The DOL parser even flags itself as incomplete in comments; use it only as a
  reminder to keep Hyperion's DOL parser strict.
- Test private keys and example CAPKs are not certification material.

### openemv/emv-utils

Inspected files and areas:

- `README.md`
- `LICENSE`
- `src/emv.h`
- `src/emv_tlv.h`
- `src/emv_dol.h`
- `src/emv_oda.h`
- `src/emv_fields.c`
- `src/iso7816_apdu.h`
- `src/pcsc.c`
- `tools/emv-decode.c`
- `tools/emv-tool.c`
- `tests/emv_dol_test.c`
- `tests/emv_build_candidate_list_test.c`
- `tests/emv_terminal_risk_management_test.c`
- `tests/emv_rsa_cda_test.c`

Useful ideas to adapt:

- Tool-first validation is excellent. `emv-decode` supports ATR, SW1/SW2, BER,
  TLV, DOL, tag list, CVM list/results, TVR, TSI, IAD, TTQ, CTQ, terminal type,
  terminal capabilities, ISO country/currency/language, and other field
  decoders. Hyperion adapts this as controlled parser-backed decoding in
  `krn_emv_decode`, including masked APDU/response handling and primitive
  tag-list inspection for SDA evidence.
- The high-level `emv_ctx_t` separates terminal transport, terminal config,
  transaction params, selected app, ICC data, terminal data, and ODA context.
  Hyperion already separates modules, but a single evidence-oriented
  transaction-context diagram would improve reviewability.
- Tests are narrow and fixture-heavy: DOL malformed-entry tests, candidate-list
  APDU scripts, processing restrictions, terminal risk management, and RSA/CDA
  tests. Hyperion should mirror this density for every certification-critical
  state-machine branch.
- DOL construction keeps the requested tag order explicit and fails malformed
  source definitions early. Hyperion adapted that validation stance by making
  CDOL1/CDOL2 runtime construction reject missing sources instead of silently
  zero-padding GENERATE AC input data.
- AFL validation treats the AFL as bounded four-byte records and validates
  field-domain edges before READ RECORD planning. Hyperion adapted the concept
  as a 252-byte / 63-entry parser bound while retaining its separate
  `MAX_RECORD_LOCATORS` execution cap.
- The README's packaging/build/test matrix across Linux, macOS, Windows, and
  CodeQL is useful as release engineering inspiration for pre-lab evidence.

Do not borrow:

- LGPL source without legal review.
- The project states it is a partial implementation mostly intended for
  validation/debugging, not a certification-ready kernel.
- Public AID/product lookup tables and field decoders should be treated as
  convenience tooling, not scheme-authoritative profile data.

### emerald79/libpay

Inspected files and areas:

- `README.md`
- `COPYING`
- `include/libpay/emv.h`
- `include/libpay/tlv.h`
- `src/libemv/emv_ep.c`
- `src/libemv/emv_tag.c`
- `src/libtlv/tlv.c`
- `src/tlvdump/tlvdump.c`
- `etc/libemv/emv-tags.json`

Useful ideas to adapt:

- The README defines a TLV-based configuration dictionary for entry point and
  kernel combinations, including AID, kernel ID, transaction types, TTQ, reader
  limits, CVM required limit, and terminal settings. Hyperion already has signed
  JSON profiles; the useful adaptation is a generated human-readable profile
  dictionary for review and lab submission.
- `emv_ep.c` models contactless entry-point states, combination sets,
  registered kernels, preprocessing indicators, TTQ adjustment, candidate list
  handling, and outcome structures. Hyperion's `selection`, `c8`, and `fsm`
  modules should keep these boundaries explicit.
- `tlvdump` supports hex/binary/text/C11 output and JSON tag descriptors.
  Hyperion's tooling could use the same input/output mode coverage while
  preserving Rust-native parsers and redaction policy.

Do not borrow:

- LGPL-3.0 source without legal review.
- The README says the project is early-stage, APIs are unstable, and it is not
  certified.
- Its C memory-management style does not fit Hyperion's Rust core.

### Switstack Moka

Inspected public material:

- Public Moka product page.
- Public Moka knowledge-base pages for overview, architecture, integration,
  configuration, EMV testing, and performance.

Useful ideas to adapt:

- Treat Moka as a process benchmark: hardware abstraction, source-available
  review, testing service, certification-oriented CI, and explicit integration
  use cases are the borrowable ideas.
- The public architecture/integration material reinforces a split between entry
  point, kernels, HAL/platform integration, and Level 3 application use cases.
  Hyperion should keep its C ABI and adapter boundary aligned with that shape.
- The testing material supports the idea that compliance software needs
  systematic test-plan execution at each commit. Hyperion's quality gate
  manifest should continue moving toward reproducible, commit-level evidence.

Do not borrow:

- No public source was inspected. Public material describes source access after
  onboarding/evaluation steps, so source review requires controlled access and
  separate legal/process controls.
- Marketing claims are not certification evidence for Hyperion.

## Hyperion Backlog Ideas

The following are adaptation candidates, ordered by near-term value:

1. Maintain and extend the `krn_emv_decode` example so lab-trace triage stays
   parser-backed, masked by default, and covers operator-facing TLV, DOL, CVM,
   primitive tag-list, bitmap, CID, GENERATE AC response, status-word, short
   command APDU, and response APDU envelope decodes before formal test-tool
   execution.
2. Continue expanding `docs/prelab_apdu_trace_pack.jsonl` beyond the current
   scenario expectation records and maintained PAN, Track 2, cryptogram,
   issuer-authentication/script, and APDU follow-up masking coverage once
   formal test-tool inputs are available.
3. Maintain the C ABI APDU script adapter for deterministic request/response
   smoke tests, and keep PC/SC or mobile NFC adapters outside the kernel core.
4. Maintain and extend the human-readable signed-profile dictionary generated
   from `docs/scheme_profiles.cert.json`, especially as lab-supplied profiles
   replace fixture material.
5. Maintain card-originated TLV admission coverage for terminal/kernel-owned
   tags and PAN/track consistency, and extend it toward private/proprietary tag
   update rules as licensed profiles define those boundaries.
6. Maintain and extend the DOL source-precedence tests across transaction
   params, terminal data, ICC data, generated unpredictable numbers, and profile
   defaults; current coverage includes rejected card attempts to overwrite
   terminal amount data and generated `9F37` values before first GAC.
7. Keep public-reference review out of the lab evidence closure path: update
   open issues only when licensed/lab evidence arrives, not when an open-source
   reference demonstrates similar behavior.

## Clean-Room Rules For Follow-Up Work

- Use references to name missing evidence, test shapes, and architectural
  boundaries.
- Do not paste or translate source code from the reviewed projects.
- Do not import public CAPK/test-key material into certification profiles.
- Do not derive scheme behavior from public projects when licensed specs or lab
  vectors are required.
- Preserve Hyperion's existing sensitive-data policy: redacted debug output,
  opaque PIN handles, masked APDU traces, and crash-safe `Debug`
  implementations.
