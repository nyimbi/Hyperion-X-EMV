## Executive assessment

The specification is a **strong orientation document**, but it is **not yet an implementation-ready, certification-ready EMV kernel specification**. It correctly identifies the main EMV transaction phases, the L1/L2/L3 stack, key architectural components, configuration concerns, certification paths, and security themes. However, it remains too narrative, contains several technical inaccuracies, and omits the exact normative structures that an engineering team, certification lab, or acquirer integration team would require. 

My rating:

| Dimension                     |   Rating | Assessment                                                                                                                                      |
| ----------------------------- | -------: | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| Conceptual coverage           | 7.5 / 10 | Good overview of EMV flow and kernel responsibilities.                                                                                          |
| Technical correctness         | 5.5 / 10 | Several serious EMV cryptography and transaction-flow errors.                                                                                   |
| Implementation readiness      |   4 / 10 | Lacks state machines, TLV catalogues, APIs, error codes, memory model, test cases, and scheme profiles.                                         |
| Certification readiness       | 4.5 / 10 | Mentions L1/L2/L3, but does not define evidence, conformance matrix, test harness, lab submission pack, or scheme-specific certification scope. |
| Security completeness         |   5 / 10 | Covers PIN/key themes, but conflates kernel, PED, HSM, issuer, acquirer, and secure element responsibilities.                                   |
| Product/specification quality |   6 / 10 | Well-structured prose, but too general and sometimes overclaims completeness.                                                                   |

The most important conclusion: **this should not yet be presented as a “complete, implementation-ready reference for building an EMV kernel that can be certified and deployed.”** That statement overstates the document’s maturity. It is better characterized as a **requirements primer** or **architectural briefing** for an EMV kernel.

---

## Major strengths

The document has a sensible macro-structure. It covers **scope**, **EMV stack position**, **transaction phases**, **architecture**, **security**, **configuration**, **certification**, **API integration**, and **design recommendations**. That is the right top-level shape for a serious EMV kernel artifact. 

It also correctly recognizes the separation between **Level 1**, **Level 2**, and **Level 3**. That distinction is fundamental: L1 concerns the card-reader interface, L2 concerns kernel behavior, and L3 concerns end-to-end terminal/acquirer integration. EMVCo similarly describes EMV Contact Chip as being based on EMV Chip Specifications and maintained with supporting approval/evaluation processes. ([EMVCo][1])

The reference to **C-8** is directionally current. EMVCo announced that testing for **Book C-8 Kernel 8** became available on **16 October 2024**, and this supports the document’s claim that C-8 certification testing became available in October 2024. ([EMVCo][2])

The recommendation to plan early certification testing is also sound. EMVCo has an established approval process for kernels, and vendors obtain approval through recognized laboratories and EMVCo’s approval infrastructure. ([EMVCo][2])

---

## Critical technical defects

### 1. The document incorrectly states that the kernel generates ARQC

The specification says the kernel “must also generate the ARQC if required” and elsewhere says the kernel assists by “constructing the ARQC using the card’s keys.” 

That is materially wrong.

In EMV, the **card generates the application cryptogram**, including **ARQC**, **TC**, or **AAC**, in response to **GENERATE AC**. The terminal/kernel constructs the **CDOL data field**, requests the cryptogram type, parses the response, and passes relevant data to the Level 3 application/host. The terminal does not possess the issuer master keys required to generate a valid ARQC. The issuer or issuer host validates the ARQC, usually using keys derived from issuer-side secret material.

This error has architectural consequences. It wrongly suggests that the kernel needs issuer cryptographic secrets. It should not.

**Replacement requirement:**

> The kernel shall construct the CDOL1/CDOL2 input data for the GENERATE AC command, request the appropriate cryptogram type, transmit the APDU to the ICC, parse the returned CID/AC/IAD/ATC and related data objects, and expose those data elements to the Level 3 application for online authorization message construction. The ICC, not the kernel, generates ARQC, TC, and AAC.

---

### 2. The document misidentifies AAC as approval

The specification says that the card returns “an Application Authentication Cryptogram (AAC) if the card approves offline.” 

That is wrong. In EMV terminology:

| Cryptogram | Meaning                                         |
| ---------- | ----------------------------------------------- |
| **ARQC**   | Online authorization requested.                 |
| **TC**     | Transaction certificate, offline approval.      |
| **AAC**    | Application authentication cryptogram, decline. |

The document later correctly lists AAC as “card declines offline,” but the earlier sentence creates a direct contradiction. 

**Required correction:** Replace the incorrect sentence with:

> The card returns ARQC when online authorization is requested, TC when the card approves offline, and AAC when the card declines.

---

### 3. The security section conflates EMV kernel responsibilities with PED, acquirer, issuer, and HSM responsibilities

The document says the kernel must securely store **Issuer Master Keys** and support **DUKPT**. 

This is a major design flaw. A normal EMV Level 2 kernel should not store **issuer master keys**. Issuer master keys are issuer-side or issuer-processor-side secrets used to derive or validate application cryptograms. The terminal may handle **CAPKs** for offline data authentication, and the secure PIN subsystem may handle PIN encryption keys, but those are not the same as issuer master keys.

Similarly, **DUKPT** is relevant to PIN encryption and transaction-originated key management in the secure PIN / PED / SRED environment, but it is not a generic kernel requirement for EMV application cryptogram processing. PCI PTS POI standards govern approved POI devices and PIN capture/security expectations; PCI SSC maintains approved PTS device listings and urges merchants to use approved PTS devices. ([PCI Security Standards Council][3]) PCI SSC has also published PCI PTS POI Modular Security Requirements v7.0, according to PCI SSC’s own site. ([PCI Security Standards Council][4])

**Required correction:** Split security responsibilities into four domains:

| Domain                        | Correct responsibility                                                                                      |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------- |
| **EMV L2 kernel**             | CAPK lookup, ODA verification, TVR/TSI setting, APDU orchestration, cryptogram response parsing.            |
| **Secure PIN/PED subsystem**  | PIN capture, PIN block formatting, online PIN encryption, offline PIN APDU handling under PCI PTS controls. |
| **Acquirer host / switch**    | ISO 8583 / ISO 20022 message processing, online PIN routing, issuer communication.                          |
| **Issuer / issuer processor** | ARQC validation, ARPC generation, issuer scripts, issuer master key custody.                                |

---

### 4. The ODA section is underspecified and partly imprecise

The document lists **SDA**, **DDA**, and **CDA**, but it does not specify the actual EMV certificate chain, data authentication records, recovered data formats, failure modes, and TVR/TSI effects. 

A certification-grade ODA section must define:

| ODA element                       | Missing detail                                                                     |
| --------------------------------- | ---------------------------------------------------------------------------------- |
| **CAPK selection**                | RID + CA Public Key Index, expiration, checksum/hash validation, modulus/exponent. |
| **Issuer Public Key Certificate** | Recovery, hash validation, issuer key reconstruction.                              |
| **ICC Public Key Certificate**    | Recovery and validation.                                                           |
| **SDA**                           | Static Data Authentication Tag List, Signed Static Application Data.               |
| **DDA**                           | INTERNAL AUTHENTICATE command, DDOL, Signed Dynamic Application Data.              |
| **CDA**                           | GENERATE AC coupling, signed dynamic data including cryptogram-related data.       |
| **TVR/TSI mutation**              | Exact bits to set on success/failure or absence.                                   |

Without this, the document is descriptive rather than executable.

---

### 5. Contact and contactless flows are not adequately separated

The document treats the EMV transaction flow as if one generalized sequence can cover both **contact** and **contactless**. That is dangerous.

Contactless kernels, especially scheme-specific kernels and C-8, have materially different requirements around:

| Area                  | Contact                                 | Contactless                                                                                       |
| --------------------- | --------------------------------------- | ------------------------------------------------------------------------------------------------- |
| Application selection | PSE/PPSE behavior differs by interface. | PPSE and Entry Point behavior are central.                                                        |
| CVM                   | Full CVM list processing in contact.    | CVM is often governed by contactless limits, CDCVM, no-CVM thresholds, and kernel-specific rules. |
| Offline approval      | Common in some contact contexts.        | Often constrained or scheme-dependent.                                                            |
| Timing                | Less stringent.                         | Strict tap latency and removal behavior.                                                          |
| Kernel selection      | Contact kernel logic.                   | Multiple kernels or C-8 unified kernel / Entry Point logic.                                       |
| Outcome signaling     | Terminal/card flow.                     | Outcome parameters, UI requests, restart/try-again/remove-card behavior.                          |

The C-8 recommendation is reasonable, but it must be framed as **contactless kernel strategy**, not as a universal replacement for all contact/contactless implementation complexity. EMVCo’s C-8 announcement explicitly concerns the **EMV Contactless Kernel Specification** and its testing process. ([EMVCo][2])

---

### 6. The specification relies on EMV 4.3, but should account for EMV 4.4

The document says contact EMV should follow **Books 1 to 4 version 4.3 or later**.  That wording is acceptable but weak. EMVCo signaled the publication of **version 4.4** of the EMV Contact Chip Specification in its 2022 priorities, including support for advances such as biometric cardholder verification and ECC. ([EMVCo][5])

**Required correction:** The specification should explicitly state:

> The implementation baseline shall be the latest EMVCo Contact Chip and Contactless specifications available at project initiation, with a controlled compliance baseline recorded in the certification conformance matrix. EMV 4.3 may be treated as a legacy compatibility floor, not the forward-looking baseline.

---

## Completeness gaps

### 1. No normative requirements taxonomy

A serious specification needs requirement identifiers and modality:

| Current form                  | Required form                                            |
| ----------------------------- | -------------------------------------------------------- |
| “The kernel must...” in prose | `EMV-KRN-FUNC-001 SHALL...`                              |
| General recommendations       | `SHOULD`, `MAY`, `SHALL NOT`                             |
| No traceability               | Requirements mapped to tests, standards, owner, evidence |

Example:

| ID              | Requirement                                                                                                                      | Modality  | Verification                      |
| --------------- | -------------------------------------------------------------------------------------------------------------------------------- | --------- | --------------------------------- |
| EMV-KRN-GAC-001 | The kernel shall construct CDOL1 data in tag order using the selected application’s CDOL1 definition before issuing GENERATE AC. | SHALL     | Unit + certification test case    |
| EMV-KRN-GAC-002 | The kernel shall not generate ARQC, TC, or AAC locally.                                                                          | SHALL NOT | Code review + architecture review |
| EMV-KRN-ODA-001 | The kernel shall validate the CAPK checksum before using a CAPK for offline data authentication.                                 | SHALL     | Unit test + negative test         |

---

### 2. No state machine

An EMV kernel is essentially a **deterministic protocol state machine**. The current specification lists phases but does not define states, transitions, events, guards, outputs, or terminal/card exceptions.

At minimum, it needs a formal model:

[
K = (S, E, C, \delta, O, \lambda)
]

where:

[
S = {\text{Idle}, \text{Initialized}, \text{AppSelection}, \text{GPO}, \text{ReadRecords}, \text{ODA}, \text{ProcessingRestrictions}, \text{CVM}, \text{TRM}, \text{TAA}, \text{GenerateAC1}, \text{Online}, \text{GenerateAC2}, \text{IssuerScript}, \text{Complete}, \text{Error}}
]

[
\delta : S \times E \times C \rightarrow S
]

and:

[
\lambda : S \times E \times C \rightarrow O
]

maps state, event, and context to outputs such as APDUs, callbacks, TVR mutations, host data, or final decision.

Without this, deterministic implementation and certification-debug reproducibility are weak.

---

### 3. No TLV data dictionary

The specification names some EMV data objects but does not define a full tag catalogue. A buildable kernel spec needs at least the core tags:

| Tag    | Name                        | Required usage            |
| ------ | --------------------------- | ------------------------- |
| `4F`   | AID                         | Application selection     |
| `50`   | Application Label           | UI/display                |
| `57`   | Track 2 Equivalent Data     | Host authorization        |
| `5A`   | PAN                         | Card data                 |
| `5F24` | Application Expiration Date | Processing restrictions   |
| `5F2A` | Transaction Currency Code   | Terminal data             |
| `82`   | AIP                         | Capability interpretation |
| `84`   | DF Name                     | Application selection     |
| `8C`   | CDOL1                       | First GENERATE AC input   |
| `8D`   | CDOL2                       | Second GENERATE AC input  |
| `8E`   | CVM List                    | CVM processing            |
| `95`   | TVR                         | Risk/result reporting     |
| `9A`   | Transaction Date            | CDOL / host data          |
| `9B`   | TSI                         | Transaction status        |
| `9C`   | Transaction Type            | Transaction context       |
| `9F02` | Amount Authorized           | CDOL / risk checks        |
| `9F10` | Issuer Application Data     | Host data                 |
| `9F26` | Application Cryptogram      | Host data                 |
| `9F27` | CID                         | Cryptogram type           |
| `9F36` | ATC                         | Host data                 |
| `9F37` | Unpredictable Number        | Cryptogram input          |

The current document cannot be implemented precisely without such a dictionary.

---

### 4. No API contract

The API section is too abstract. It says the kernel provides a “well-defined API,” but it does not actually define one. 

A proper API section must specify:

```c
typedef enum {
    EMV_OK = 0,
    EMV_ERR_INVALID_STATE,
    EMV_ERR_MISSING_TAG,
    EMV_ERR_CARD_BLOCKED,
    EMV_ERR_ODA_FAILED,
    EMV_ERR_CVM_FAILED,
    EMV_ERR_HOST_TIMEOUT,
    EMV_ERR_SCRIPT_FAILED
} emv_status_t;

typedef enum {
    EMV_OUTCOME_APPROVED_OFFLINE,
    EMV_OUTCOME_DECLINED_OFFLINE,
    EMV_OUTCOME_GO_ONLINE,
    EMV_OUTCOME_APPROVED_ONLINE,
    EMV_OUTCOME_DECLINED_ONLINE,
    EMV_OUTCOME_TRY_AGAIN,
    EMV_OUTCOME_TERMINATED
} emv_outcome_t;
```

It also needs a complete callback model:

| Callback                     | Purpose                                  |
| ---------------------------- | ---------------------------------------- |
| `transmit_apdu()`            | Send C-APDU and return R-APDU.           |
| `request_pin()`              | Invoke secure PIN entry.                 |
| `display_message()`          | Terminal UI messaging.                   |
| `select_application()`       | Cardholder AID selection where required. |
| `authorize_online()`         | Host authorization delegation to L3.     |
| `get_unpredictable_number()` | Secure/random terminal nonce generation. |
| `get_transaction_time()`     | Clock source.                            |
| `load_config()`              | AID/CAPK/TAC/floor-limit configuration.  |
| `log_event()`                | Structured masked logging.               |

---

### 5. No error handling taxonomy

The current specification says failures should “terminate or fall back” depending on scheme rules.  That is insufficient.

It needs deterministic handling for:

| Failure class          | Examples                                                                            |
| ---------------------- | ----------------------------------------------------------------------------------- |
| **Card communication** | Timeout, SW1/SW2 errors, malformed TLV, card removed.                               |
| **Data integrity**     | Missing mandatory tag, duplicate primitive tag, invalid length, inconsistent AFL.   |
| **ODA failure**        | Missing CAPK, expired CAPK, certificate recovery failure, hash mismatch.            |
| **CVM failure**        | PIN try limit exceeded, PIN pad unavailable, offline PIN failed, CDCVM unavailable. |
| **Risk failure**       | Floor limit exceeded, random selection triggered, exception file hit.               |
| **Host failure**       | Timeout, malformed authorization response, ARPC unavailable, script failure.        |
| **State failure**      | API called out of sequence, duplicate completion, reset during APDU exchange.       |

---

### 6. No scheme-specific profiles

The document refers to Visa, Mastercard, Amex, Discover, JCB, and so on, but does not define a scheme abstraction. 

A real implementation needs a profile model:

```yaml
scheme_profile:
  rid: "A000000003"
  scheme: "Visa"
  interfaces:
    contact: true
    contactless: true
  aids:
    - aid: "A0000000031010"
      priority: 10
      partial_selection: true
  tac:
    denial: "..."
    online: "..."
    default: "..."
  limits:
    floor_limit: 0
    cvm_limit: 0
    contactless_transaction_limit: 0
  capk_set:
    version: "2026-Q2"
  kernel:
    contactless_kernel_id: "C-8 or scheme-specific"
```

Without scheme profiles, the implementation will become hardcoded and certification-fragile.

---

### 7. No privacy, data minimization, or PCI DSS treatment

The specification mentions masking logs but does not define **PAN truncation**, **sensitive authentication data handling**, **track data retention prohibitions**, **secure logging rules**, or **debug-mode controls**. 

For a payment kernel embedded in a POI environment, this omission is material. The document should define:

| Data                    | Rule                                                                         |
| ----------------------- | ---------------------------------------------------------------------------- |
| PAN                     | Mask in logs except permitted digits.                                        |
| Track 2 equivalent data | Never log unmasked.                                                          |
| PIN/PIN block           | Never log, persist, or expose to application memory.                         |
| ARQC/ARPC               | Log only if allowed by certification/debug policy and masked where required. |
| APDU logs               | Configurable, masked, disabled in production unless certified support mode.  |
| Crash dumps             | Must exclude cardholder data and secrets.                                    |

---

### 8. No performance model

The document states `<300 ms` for contact and `<150 ms` for contactless.  These are not decomposed into a latency budget, and may be unrealistic or ambiguous depending on whether the figure excludes cardholder interaction, host authorization, RF activation, card response latency, and UI delays.

A better specification defines:

[
T_{\text{txn}} = T_{\text{L1}} + T_{\text{APDU}} + T_{\text{TLV}} + T_{\text{ODA}} + T_{\text{CVM}} + T_{\text{risk}} + T_{\text{host}} + T_{\text{script}}
]

Then separately constrains:

| Segment                     | Bound                                  |
| --------------------------- | -------------------------------------- |
| TLV parse/compose           | deterministic microbenchmark           |
| ODA RSA verification        | per-key-size timing                    |
| APDU dispatcher overhead    | excluding card response latency        |
| Contactless outcome latency | excluding cardholder presentation time |
| Host authorization          | explicitly outside L2 kernel latency   |

---

## Section-by-section quality review

| Section                      | Quality | Main issue                                                                           | Required action                                                                          |
| ---------------------------- | ------: | ------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------- |
| 1. Scope and Definitions     |    Good | C-8 framed too broadly.                                                              | Distinguish contact, contactless, Entry Point, C-8, and scheme kernels.                  |
| 2. Transaction Flow          |  Medium | Correct high-level phases, but critical cryptogram errors.                           | Add state machine, CDOL/DDOL/TDOL, TVR/TSI bit-setting, exception flows.                 |
| 3. Architecture              |  Medium | Sensible components, but no interfaces or memory/concurrency model.                  | Add component contracts, callback ABI, threading model, deterministic context ownership. |
| 4. Security                  |    Weak | Conflates issuer keys, DUKPT, CAPKs, PED, HSM, and kernel responsibilities.          | Split cryptographic trust domains.                                                       |
| 5. Configuration             |  Medium | Good categories, but no schema, versioning, signing, rollback, or AID profile model. | Add signed configuration schema and lifecycle.                                           |
| 6. Certification and Testing |  Medium | Accurate orientation, weak evidence model.                                           | Add conformance matrix, lab submission pack, test coverage map.                          |
| 7. API and Integration       |    Weak | No actual API.                                                                       | Define C ABI, callbacks, data structures, error codes, event model.                      |
| 8. Design Recommendations    |    Good | Useful but non-normative.                                                            | Move into architecture rationale appendix.                                               |
| References                   |    Weak | Not citation-grade.                                                                  | Add URLs, version numbers, retrieval dates, normative vs informative classification.     |

---

## High-priority rewrite plan

### Priority 0: Fix incorrect EMV semantics

Correct these immediately:

| Current claim                                           | Problem               | Correct version                                                                                                        |
| ------------------------------------------------------- | --------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| Kernel generates ARQC                                   | Wrong trust boundary. | Card generates ARQC in response to GENERATE AC.                                                                        |
| AAC approves offline                                    | Wrong.                | TC approves offline; AAC declines.                                                                                     |
| Kernel stores issuer master keys                        | Wrong and unsafe.     | Issuer keys remain issuer/host-side; kernel stores or accesses CAPKs and delegates PIN/security operations.            |
| Offline PIN encrypted with DUKPT before sending to card | Imprecise.            | Offline PIN uses EMV VERIFY mechanisms through secure PIN entry handling; online PIN uses encrypted PIN block to host. |
| Any processing restriction mismatch leads to denial     | Too absolute.         | Set TVR bits and apply terminal/card action analysis per scheme rules.                                                 |
| ODA failure means decline online                        | Imprecise phrasing.   | ODA failure sets TVR bits; terminal action analysis determines AAC/ARQC path subject to rules.                         |

---

### Priority 1: Convert prose into testable requirements

Add a requirements catalogue with this structure:

| Field               | Meaning                                                         |
| ------------------- | --------------------------------------------------------------- |
| Requirement ID      | Stable identifier.                                              |
| Requirement text    | One atomic SHALL/SHOULD/MAY statement.                          |
| Source              | EMV Book / scheme / PCI / internal.                             |
| Applies to          | Contact, contactless, C-8, all.                                 |
| Verification method | Unit, integration, certification, code review, static analysis. |
| Evidence artifact   | Test log, trace, code review record, lab result.                |

---

### Priority 2: Add formal state machine

At minimum, add:

| State        | Entry condition         | Exit condition                | Error transitions           |
| ------------ | ----------------------- | ----------------------------- | --------------------------- |
| Idle         | Kernel initialized      | Transaction parameters loaded | Invalid config              |
| AppSelection | Card detected           | AID selected                  | No mutually supported AID   |
| GPO          | AID selected            | AIP/AFL parsed                | GPO failed                  |
| ReadRecords  | AFL available           | Mandatory records read        | Missing/malformed record    |
| ODA          | Records available       | ODA result recorded           | CAPK/certificate failure    |
| CVM          | CVM list available      | CVM result recorded           | CVM failed                  |
| TAA          | TVR/TSI/risk available  | AC request decision           | Terminal decline            |
| GenerateAC1  | CDOL1 constructed       | ARQC/TC/AAC parsed            | Malformed cryptogram        |
| Online       | ARQC present            | Host response parsed          | Timeout/failure             |
| GenerateAC2  | Host response available | Final AC parsed               | Card decline/script failure |
| Complete     | Outcome determined      | Context reset                 | Idempotency guard           |

---

### Priority 3: Add a TLV and APDU annex

The document must specify mandatory APDUs:

| APDU                     | Purpose                                                   |
| ------------------------ | --------------------------------------------------------- |
| `SELECT`                 | Select PPSE/PSE/application.                              |
| `GET PROCESSING OPTIONS` | Obtain AIP/AFL.                                           |
| `READ RECORD`            | Read application records.                                 |
| `GET DATA`               | Retrieve selected data such as counters where applicable. |
| `INTERNAL AUTHENTICATE`  | DDA where applicable.                                     |
| `VERIFY`                 | Offline PIN verification.                                 |
| `GENERATE AC`            | Request ARQC/TC/AAC.                                      |
| `EXTERNAL AUTHENTICATE`  | Issuer authentication where applicable.                   |
| Issuer script commands   | Post-authorization card update.                           |

Each APDU should define command structure, expected SW1/SW2 handling, input data, output TLVs, and state transition.

---

### Priority 4: Define certification evidence

Add a certification readiness matrix:

| Evidence artifact                      | Required for               |
| -------------------------------------- | -------------------------- |
| EMVCo conformance statement            | L2 submission              |
| Kernel version manifest                | L2 submission              |
| CAPK/configuration manifest            | L2 and deployment          |
| Trace logs with masked APDUs           | Lab debugging              |
| Unit test report                       | Internal quality gate      |
| Integration simulator report           | Pre-lab gate               |
| Static analysis report                 | Secure coding gate         |
| Fuzzing report for TLV/APDU parser     | Robustness gate            |
| Cryptographic module boundary document | Security review            |
| PCI PTS integration statement          | POI/PIN security alignment |

---

## Recommended target structure for v2

A stronger version should be reorganized as follows:

1. **Executive Scope and Certification Boundary**
2. **Normative References and Version Baseline**
3. **Kernel Trust Boundary and Responsibility Model**
4. **Supported Interfaces: Contact, Contactless, C-8**
5. **Transaction State Machine**
6. **Application Selection and Kernel Selection**
7. **EMV Data Object Dictionary**
8. **APDU Command Specification**
9. **ODA Specification: SDA, DDA, CDA**
10. **Processing Restrictions and TVR/TSI Mutation Rules**
11. **CVM Processing**
12. **Terminal Risk Management**
13. **Terminal and Card Action Analysis**
14. **Generate AC and Cryptogram Handling**
15. **Online Authorization Interface to L3**
16. **Issuer Authentication and Script Processing**
17. **Configuration Model: AID, CAPK, TAC, Limits, Scheme Profiles**
18. **Security Architecture: CAPK, PIN, Key Boundaries, Logging, PCI PTS**
19. **API/ABI Specification**
20. **Error Handling and Recovery**
21. **Performance and Resource Constraints**
22. **Testing Strategy: Unit, Integration, Fuzz, Simulator, Lab**
23. **Certification Evidence Matrix**
24. **Deployment, OTA Updates, Rollback, Versioning**
25. **Appendices: TLV Catalogue, APDU Catalogue, Test Vectors, Trace Format**

---

## Final verdict

The current specification is **useful as a senior management or engineering orientation note**, but it is **not sufficient for a development team to build a certifiable EMV L2 kernel**.

The document’s largest risks are:

1. **Incorrect cryptogram responsibility**, especially the claim that the kernel generates ARQC.
2. **Incorrect AAC semantics**, where AAC is at one point described as offline approval.
3. **Unsafe key-management boundary**, especially references to issuer master keys inside the kernel.
4. **Absence of formal state machine, TLV dictionary, APDU contract, API contract, and error taxonomy**.
5. **Insufficient separation of contact, contactless, scheme-specific, and C-8 behavior**.
6. **Overclaiming implementation readiness and certification readiness**.

The fastest path to quality is not to expand the prose. It is to convert the document into a **normative engineering specification** with requirement IDs, state transitions, APDU/TLV tables, callback interfaces, test mappings, and certification evidence.

[1]: https://www.emvco.com/emv-technologies/emv-contact-chip/?utm_source=chatgpt.com "EMV® Contact Chip"
[2]: https://www.emvco.com/news/emvco-launches-the-emv-contactless-kernel-testing-process/?utm_source=chatgpt.com "EMVCo Launches the EMV® Contactless Kernel Testing ..."
[3]: https://listings.pcisecuritystandards.org/assessors_and_solutions/vpa_agreement.php?agree=true&return=%2Fassessors_and_solutions%2Fpin_transaction_devices&utm_source=chatgpt.com "Approved PTS Devices"
[4]: https://www.pcisecuritystandards.org/?utm_source=chatgpt.com "PCI Security Standards Council – Protect Payment Data with ..."
[5]: https://www.emvco.com/knowledge-hub/emv-technologies-2022-priorities/?utm_source=chatgpt.com "EMV® Technologies: 2022 Priorities"
