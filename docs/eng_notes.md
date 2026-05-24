## Short answer

**Yes, but only as a build scaffold, not as a complete implementation specification.**

An engineering team could use the current specification and annexes to begin **architecture, module decomposition, API design, parser development, test-harness setup, and non-cryptographic transaction-flow implementation**. It is **not sufficient by itself** for a team to build a certifiable EMV Level 2 kernel without further standard-specific, scheme-specific, and lab-validated inputs.

The current package should be labelled:

> **Engineering implementation scaffold / pre-certification build baseline. Not final certification implementation authority.**

---

## What the team can build from it now

The specification is sufficient to start building the following components:

| Component                          | Build readiness | Reason                                                                                               |
| ---------------------------------- | --------------: | ---------------------------------------------------------------------------------------------------- |
| **Kernel module architecture**     |            High | Trust boundaries, kernel/PED/L3/acquirer/issuer split are now coherent.                              |
| **PSE/PPSE application selection** |            High | Contact `1PAY.SYS.DDF01` and contactless `2PAY.SYS.DDF01` are now correctly specified.               |
| **TLV parser foundation**          |     Medium-high | The TLV catalogue is structurally usable and materially expanded, though not fully profile-complete. |
| **DOL parser and CDOL assembly**   |     Medium-high | CDOL/DDOL/PDOL as tag-length lists are correctly framed.                                             |
| **CID decoding**                   |            High | `CID & 0xC0` mapping is now implementation-safe.                                                     |
| **TAA engine skeleton**            |     Medium-high | TAC/IAC logic and deterministic fallback keys are present.                                           |
| **API/ABI layer**                  |     Medium-high | Core functions and callbacks are defined enough for an implementation prototype.                     |
| **Logging/masking policy**         |          Medium | Good direction, but needs production security hardening.                                             |
| **State machine harness**          |     Medium-high | The CSV is expanded, machine-validated, and authoritative for repository behavior; licensed/lab reconciliation is still required. |
| **Traceability framework**         |          Medium | Useful structure, but not yet mapped to verified lab/tool IDs.                                       |

The manifest now honestly describes the artifact set as a **Draft for Certification** and says actual cryptographic values, CAPKs, and test vectors must still be supplied during certification. That is the right framing. 

---

## What the team cannot safely build from it yet

They should **not** implement final cryptographic certification logic from the current annexes.

The ODA vectors are explicitly described as **placeholders for lab-supplied cryptographic data**, so they cannot validate real SDA, DDA, or CDA behavior. 

The scheme profile file has the right shape, including deterministic TAA fallback keys, but it still uses synthetic-looking CAPKs and profile values that require replacement or validation against real scheme/lab data. 

The lab manifest now treats repository-controlled artifacts such as source code,
the ABI conformance JSON, and reproducible-build provenance as available, but
the unit test report, integration report, static analysis report, fuzzing
report, PCI PTS integration statement, signed EMVCo/lab conformance template,
APDU traces, device evidence, and approval artifacts are still external
attachments.

So the engineering team cannot yet claim:

* **EMVCo L2 conformance**
* **scheme approval readiness**
* **valid ODA cryptographic behavior**
* **real CAPK/profile correctness**
* **complete contactless C-8 behavior**
* **final lab traceability**

---

## Minimum missing items before full implementation freeze

Before engineering freeze, the team needs these additional artifacts:

| Missing artifact                                    | Why it matters                                                                                                                     |
| --------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| **Licensed EMV Book 3 reconciliation table**        | Ensures TVR, TSI, CVM, ODA, GAC, and TAA behavior exactly match the standard.                                                      |
| **Scheme-specific implementation profiles**         | Visa, Mastercard, Amex, Discover, and C-8 behavior diverge in important details.                                                   |
| **Real CAPK set with provenance**                   | Required for ODA and certification.                                                                                                |
| **Executable ODA vectors**                          | Needed to test SDA, DDA, CDA, certificate recovery, and failure paths.                                                             |
| **Licensed APDU/SW reconciliation matrix**          | Repository SW handling is state-specific, but final certification still needs licensed/lab crosswalk coverage.                     |
| **Licensed state-machine reconciliation**           | The repository annex covers selection loops, AFL processing, scripts, issuer authentication, contactless outcomes, retries, timeouts, and fallback; the remaining blocker is lab/tool acceptance. |
| **CVM code catalogue validated against EMV Book 3** | Current CVM framing is improved, but must be validated against the licensed standard.                                              |
| **Lab/tool test-case crosswalk**                    | Converts internal test IDs into actual certification evidence.                                                                     |

---

## Recommended engineering use

The team can proceed in **three controlled tracks**.

### Track 1: Safe to implement now

Build these immediately:

* TLV parser and serializer.
* DOL parser.
* APDU dispatcher abstraction.
* Kernel context model.
* PSE/PPSE selection.
* Candidate AID selection framework.
* CID decoder.
* TVR/TSI storage and symbolic bit-setting layer.
* TAC/IAC mask evaluator.
* API/ABI wrapper.
* Logging and masking framework.
* Test harness for scripted APDU replay.
* Configuration loader and schema validation.

### Track 2: Implement behind feature flags pending validation

Build these, but mark as **standard-validation pending**:

* CVM list evaluation.
* Terminal risk management.
* ODA certificate recovery.
* SDA/DDA/CDA engines.
* Issuer authentication.
* Issuer script processing.
* Contactless C-8 outcome handling.
* Offline PIN integration through the PED secure-handle model.

### Track 3: Do not finalize until lab/scheme inputs arrive

Hold final behavior for:

* Real CAPK profiles.
* Real scheme TAC/IAC/limit parameters.
* C-8 profile-specific behavior.
* CDA request encoding.
* ODA test vectors.
* Official EMVCo/tool test case mapping.

---

## Engineering sufficiency rating

| Use case                                 |       Rating |
| ---------------------------------------- | -----------: |
| Start architecture and implementation    |   **8 / 10** |
| Build an internal prototype              | **7.5 / 10** |
| Build a full functional kernel simulator | **6.5 / 10** |
| Build a production EMV L2 kernel         | **5.5 / 10** |
| Submit to certification lab              | **3.5 / 10** |

---

## Final answer

**The specification is sufficient for an engineering team to start building, but not sufficient to complete or certify the kernel.**

It is strong enough as a **development scaffold**. It is not yet strong enough as the **single source of truth for a certifiable EMV L2 implementation**. The team should proceed, but with a formal **open-issues register** and a clear rule:

> Any behavior involving ODA, CDA, CVM, scheme profiles, CAPKs, C-8, issuer scripts, or lab test evidence remains provisional until reconciled against licensed EMVCo/scheme documentation and lab-approved test data.

The formal open-issues register is `docs/certification_open_issues.md`. Keep
that register aligned with the lab submission manifest whenever external
evidence is added, rejected, or superseded.
Yes, **some data can be plugged in after the build**, but only if the kernel is deliberately architected as a **data-driven, profile-driven EMV engine**. Some items must be fixed in code before certification because they define protocol behavior, state transitions, security boundaries, or certified kernel logic.

## The right distinction

| Category                    | Can be plugged in after build? | Examples                                                                                                                                                                                            |
| --------------------------- | -----------------------------: | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Configuration data**      |                        **Yes** | CAPKs, AIDs, TACs, floor limits, CVM limits, contactless limits, terminal country/currency, UI messages, deterministic TAA fallback choices.                                                        |
| **Certification test data** |                        **Yes** | ODA test vectors, APDU scripts, expected traces, test-case mappings, lab submission metadata.                                                                                                       |
| **Scheme profile data**     |                 **Mostly yes** | Scheme AID profiles, CAPK sets, contactless limits, kernel selection rules, permitted fallback behavior, CDCVM flags.                                                                               |
| **Protocol algorithms**     |                         **No** | TLV parsing, DOL construction, APDU construction, AFL traversal, ODA certificate recovery, CVM list evaluation, TAA algorithm, GENERATE AC handling.                                                |
| **Security boundaries**     |                         **No** | PED-owned PIN model, secure handle semantics, no issuer keys in kernel, no PIN exposure, logging redaction.                                                                                         |
| **Certified behavior**      |                 **Not safely** | C-8 outcome behavior, CDA verification logic, issuer script sequencing, contactless restart/try-again behavior. These may be parameterized, but the engine logic must already exist and be correct. |

So the answer is:

> **Build the kernel engine now, but make every scheme, CAPK, limit, TAC/IAC, AID, and lab vector externally loadable through signed configuration. Do not postpone protocol logic.**

---

## What can safely be plugged in later

The following can and should be externalized into signed configuration:

| Data type                          | Plug-in mechanism                                                            |
| ---------------------------------- | ---------------------------------------------------------------------------- |
| **CAPKs**                          | Signed CAPK bundle indexed by `RID + key_index`.                             |
| **AIDs**                           | Signed scheme profile with AID, priority, interface, partial-selection rule. |
| **TACs**                           | Per-scheme/per-AID signed configuration.                                     |
| **IAC defaults**                   | Runtime card-supplied values, with profile fallback rules.                   |
| **Floor limits**                   | Per-AID, per-interface, per-merchant profile.                                |
| **CVM limits**                     | Contact/contactless, per scheme, per country/acquirer.                       |
| **Contactless transaction limits** | Profile data.                                                                |
| **CDCVM policy**                   | Contactless/scheme profile.                                                  |
| **TAA fallback keys**              | Required per scheme/AID profile.                                             |
| **CDA request encoding**           | Profile-defined, but only if the kernel has the correct CDA engine.          |
| **UI messages**                    | Contactless outcome/profile data.                                            |
| **ODA vectors**                    | Test fixture data, not production kernel data.                               |
| **Lab test IDs**                   | Traceability metadata.                                                       |
| **Acquirer host field mapping**    | Preferably Level 3 configuration, not L2 kernel code.                        |

This is exactly how you avoid rebuilding firmware every time schemes update CAPKs, AIDs, limits, or risk parameters.

---

## What cannot be plugged in later without rework

These must be correctly implemented before the engineering build stabilizes:

| Non-pluggable item                | Why                                                                                              |
| --------------------------------- | ------------------------------------------------------------------------------------------------ |
| **BER-TLV parser**                | All EMV data handling depends on it.                                                             |
| **DOL parser**                    | PDOL, CDOL1, CDOL2, DDOL, TDOL construction require correct tag-length processing.               |
| **APDU dispatcher**               | Must support exact command/response lifecycle and SW1/SW2 handling.                              |
| **Application selection engine**  | PSE/PPSE/direct AID selection and candidate-list behavior are protocol logic.                    |
| **AFL record traversal**          | Cannot be “configured in” later; it is core EMV behavior.                                        |
| **TVR/TSI mutation layer**        | Must be a deterministic bit-setting subsystem.                                                   |
| **CVM list evaluator**            | The CVM code/condition-code algorithm is core logic.                                             |
| **TAA engine**                    | The engine can consume TAC/IAC data, but the evaluation algorithm must be correct.               |
| **GENERATE AC handling**          | P1 encoding, CID decoding, CDOL construction, and AC response parsing are core.                  |
| **ODA engine**                    | CAPKs are data, but certificate recovery, hash verification, SDA/DDA/CDA logic are code.         |
| **Issuer script sequencing**      | Tags `71` and `72`, before/after final AC processing, and result reporting are behavior.         |
| **Contactless/C-8 outcome model** | Outcome construction, UI requests, restart behavior, and alternate-interface handling are logic. |
| **PED secure handle boundary**    | Must be designed into the ABI. It cannot be patched in cleanly later.                            |

---

## Recommended architecture

Use a **two-layer model**:

[
\text{Kernel} = \text{Certified Protocol Engine} + \text{Signed Runtime Profiles}
]

The engine should implement invariant EMV behavior:

[
E = { \text{TLV}, \text{DOL}, \text{APDU}, \text{ODA}, \text{CVM}, \text{TRM}, \text{TAA}, \text{GAC}, \text{Scripts}, \text{C8Outcome} }
]

The profile supplies variable parameters:

[
P = { \text{AIDs}, \text{CAPKs}, \text{TACs}, \text{limits}, \text{fallbacks}, \text{CVM policies}, \text{CDA controls}, \text{UI strings} }
]

At runtime:

[
\text{Decision} = E(\text{CardData}, \text{TransactionData}, P)
]

This lets you plug in missing data later without rewriting core logic.

---

## Build strategy

### Phase 1: Build the invariant engine

Implement:

* TLV parser.
* DOL parser.
* APDU transport abstraction.
* PSE/PPSE/direct AID selection.
* GPO and AFL traversal.
* TVR/TSI subsystem.
* CVM evaluator.
* TRM engine.
* TAA engine.
* GENERATE AC handler.
* ODA framework.
* Script processor.
* C-8 outcome abstraction.
* Signed configuration loader.
* Trace replay harness.

Use synthetic profiles only for development, clearly marked:

```json
{
  "profile_status": "synthetic_dev_only",
  "certification_use": false
}
```

### Phase 2: Plug in official data

Replace development profiles with:

* Scheme-approved AIDs.
* Scheme/acquirer-approved CAPKs.
* Actual TAC/defaults.
* Acquirer limits.
* Contactless/CVM limits.
* Official C-8 profile data.
* Lab test vectors.
* Test tool references.

### Phase 3: Freeze certification build

At certification freeze:

```text
kernel_binary_hash
config_bundle_hash
capk_bundle_hash
scheme_profile_hash
test_vector_hash
traceability_matrix_hash
```

must all be recorded in the lab submission manifest.

The generated evidence checklist in
`docs/certification_evidence_checklist.json` and
`docs/certification_evidence_checklist.md` is the requirement map for this
freeze. The generated intake ledger in `docs/certification_evidence_intake.json`
and `docs/certification_evidence_intake.md` is the attachment-control surface
for crowdsourced testing and lab package assembly. The generated freeze
manifest in `docs/certification_freeze_manifest.json` and
`docs/certification_freeze_manifest.md` is the submitted-build hash binding
surface. The generated security assessment plan in
`docs/certification_security_assessment_plan.json` and
`docs/certification_security_assessment_plan.md` maps `CERT-OPEN-008` review
surfaces to repository evidence and third-party assessor evidence requirements.
Each `CERT-OPEN-*` row must carry an authority, attachment, hash, date,
submitted-build scope, disposition, supersession history, and acceptance gate
before the corresponding open issue can close.

---

## The key certification point

If you plug in data later, certification must be run against the **exact combination** of:

[
(\text{Kernel Binary}, \text{Configuration Bundle}, \text{CAPK Set}, \text{Scheme Profiles}, \text{Target Device}, \text{L1 Interface})
]

A later data change may require **regression testing** or even **re-approval**, depending on the change.

| Later change                | Likely impact                                       |
| --------------------------- | --------------------------------------------------- |
| CAPK update                 | Usually controlled configuration update/regression. |
| New AID                     | May require scheme/acquirer testing.                |
| TAC/limit change            | Requires regression and acquirer approval.          |
| New CVM behavior            | Likely certification-impacting.                     |
| C-8 outcome behavior change | Certification-impacting.                            |
| ODA algorithm change        | Certification-impacting.                            |
| APDU/state-machine change   | Certification-impacting.                            |
| PED integration change      | PCI/security-impacting.                             |

---

## Practical answer for your team

**Yes, build now.** But structure the build so that missing data is isolated in signed profiles and test fixtures.

The engineering team should not block on real CAPKs or lab ODA vectors to build:

* parsers,
* state machine,
* API,
* APDU harness,
* profile loader,
* TAA engine,
* logging,
* test framework.

But they **must not hardcode synthetic data** or assume placeholder behavior is production behavior.

The implementation rule should be:

> **No scheme-specific value, CAPK, limit, TAC/IAC, CDA encoding, or certification vector may be compiled into the kernel. Everything variable must live in a signed, versioned profile bundle.**

That makes later plug-in feasible and controlled.
