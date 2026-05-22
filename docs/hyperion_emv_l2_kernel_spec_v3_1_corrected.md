# Hyperion-KRN EMV Level 2 Kernel Specification v3.1

**Document title:** Hyperion-KRN EMV Level 2 Kernel Specification  
**Version:** 3.1 corrected baseline  
**Status:** Engineering baseline pending licensed EMVCo and scheme conformance review  
**Prepared for:** Hyperion POI / POS / mPOS / kiosk integration  
**Primary purpose:** Define a deterministic, testable, certification-oriented EMV Level 2 kernel specification without misplacing issuer, acquirer, PED, or Level 3 responsibilities.

## Important conformance note

This document is written to be technically conservative. It corrects the previous draft’s known defects and avoids inventing payment-scheme constants, CAPKs, issuer action codes, terminal action codes, or executable cryptographic test vectors. Where exact values are owned by EMVCo, payment schemes, acquirers, processors, or certification laboratories, this specification references the authoritative source and requires the implementation to bind to the licensed source during certification.

This document is therefore an **engineering baseline**, not a substitute for the licensed EMVCo Books, EMV Contactless Book C-8, scheme kernel specifications, acquirer L3 requirements, PCI PTS POI requirements, or laboratory test plans.

A build is production-certifiable only when this specification, the implemented code, the signed configuration package, the scheme profiles, the CAPK set, the test traces, and the certification conformance statement have been checked against the licensed normative references.

---

# 1. Scope, certification boundary, and normative hierarchy

## 1.1 Scope

The Hyperion-KRN kernel is an **EMV Level 2 software component**. It executes the EMV transaction protocol between a Level 3 terminal application and an integrated Level 1 card interface. It applies application selection, GPO handling, AFL record reading, offline data authentication, processing restrictions, cardholder verification decisioning, terminal risk management, terminal action analysis, GENERATE AC orchestration, issuer authentication support, issuer script execution, and final outcome production.

The kernel supports:

| Interface | Protocol family | Kernel class | Certification treatment |
|---|---|---|---|
| Contact | ISO/IEC 7816 contact card protocol | EMV contact Level 2 kernel | EMV contact L2 approval and scheme/acquirer requirements |
| Contactless | ISO/IEC 14443-4 contactless APDU transport | EMV contactless kernel, including C-8 where certified | EMV Contactless kernel approval and scheme/acquirer requirements |
| Dual-interface POI | Runtime selection between contact and contactless | Separate contact and contactless logic under one product boundary | Both certification scopes apply |

The kernel does **not** implement:

1. The physical or electrical card interface. That is Level 1.
2. Secure PIN entry hardware, PED keypad control, PIN encryption key custody, or tamper-response logic.
3. Acquirer or issuer host authorization messaging as a payment switch or host system.
4. Issuer master key custody.
5. Issuer-side ARQC validation or issuer-side ARPC generation.
6. Receipt printing, merchant workflow, settlement, reversal, batching, or merchant user interface beyond callbacks and outcome data.

## 1.2 Normative hierarchy

If this specification conflicts with a licensed normative standard, the external standard prevails.

| Priority | Source | Applies to |
|---:|---|---|
| 1 | Licensed EMVCo Contact Chip Specifications, Books 1 to 4, current certified baseline | Contact EMV protocol, data objects, APDU behavior, ODA, CVM, TAA, scripts |
| 2 | Licensed EMV Contactless Specifications, including Book C-8 where claimed | Contactless Entry Point, kernel activation, outcome processing, UI requests, limits |
| 3 | Payment-scheme kernel and terminal integration specifications | Visa, Mastercard, Amex, Discover, JCB, UnionPay, domestic schemes, or C-8 certified profiles |
| 4 | Acquirer and processor L3 requirements | ISO 8583/ISO 20022 fields, online message packing, reversal, advice, settlement implications |
| 5 | PCI PTS POI and related PCI payment terminal standards | PED, PIN entry, tamper, secure display, SRED where applicable |
| 6 | This Hyperion-KRN specification | Product-level engineering, API, state model, configuration, test evidence |

## 1.3 Normative references

| ID | Reference | Required use |
|---|---|---|
| EMV-CONTACT | EMVCo Contact Chip Specifications, Books 1 to 4, current certified baseline | Contact kernel behavior and Book 3 transaction processing |
| EMV-CL | EMVCo Contactless Specifications | Contactless transaction model, Entry Point, UI/outcome behavior |
| EMV-C8 | EMV Contactless Kernel Specification, Book C-8, where claimed and licensed | Unified contactless kernel behavior |
| EMV-L2 | EMVCo Level 2 approval process and current laboratory submission rules | Certification process and product approval |
| ISO-7816-3 | ISO/IEC 7816-3 | Contact communication protocol |
| ISO-7816-4 | ISO/IEC 7816-4 | APDU structure and interindustry commands |
| ISO-14443-4 | ISO/IEC 14443-4 | Contactless APDU transport |
| ISO-9564-1 | ISO 9564-1 | PIN block formats for online PIN path, subject to PED/acquirer implementation |
| PCI-PTS-POI | PCI PTS POI Modular Security Requirements, current approved version for target product | PED and secure PIN-entry integration |

## 1.4 Requirement language

The following modal terms are normative:

| Term | Meaning |
|---|---|
| SHALL | Mandatory requirement |
| SHALL NOT | Mandatory prohibition |
| SHOULD | Recommended unless a documented exception is approved |
| MAY | Optional capability |
| PROFILE-DEFINED | Must be resolved by the certified scheme, acquirer, or product profile |
| LICENSED-SPEC-DEFINED | Must be resolved directly from a licensed normative specification and must not be inferred |

All implementation requirements use the identifier format:

```text
KRN-<DOMAIN>-<NNN>
```

Example: `KRN-GAC-004`.

---

# 2. Trust boundary and responsibility model

## 2.1 Component responsibility matrix

| Component | Responsibilities | Security classification | Kernel interaction |
|---|---|---|---|
| Hyperion-KRN EMV L2 kernel | EMV transaction state machine, APDU orchestration, TLV parsing, DOL construction, TVR/TSI mutation, ODA verification, CVM decisioning, TRM, TAA, cryptogram response parsing, issuer script APDU dispatch | Integrity-critical | Owns deterministic L2 behavior |
| Level 1 interface | Contact electrical/protocol layer, contactless RF/protocol layer, card detection, APDU transport | Hardware/protocol-critical | Exposed through `transmit_apdu` callback |
| PCI PTS PED | PIN capture, PIN display/control, secure PIN block construction, offline PIN secure handling, online PIN encryption, tamper response | Confidentiality-critical and tamper-critical | Exposed through secure PIN callbacks and handles |
| Level 3 application | Merchant workflow, UI, receipt, host communication, reversals, settlement, batch, application lifecycle | Functional and PCI-scope-dependent | Receives kernel requests and outcome data |
| Acquirer / processor / switch | Authorization routing, ISO 8583 or ISO 20022 host messaging, network rules | Host-system-critical | Receives ICC data from Level 3 |
| Issuer / issuer processor | Issuer master keys, ARQC validation, ARPC generation, issuer scripts, account decisioning | Confidentiality-critical | Indirect via acquirer/host response |

## 2.2 Cryptographic trust boundary

| Object | Secret? | Stored by kernel? | Kernel role |
|---|---:|---:|---|
| CAPK | No, public trust anchor | Yes, in signed integrity-protected configuration | Select and use for offline public-key verification |
| Issuer public key certificate | No, card-provided signed certificate | Transaction memory only | Recover and validate using CAPK |
| ICC public key certificate | No, card-provided signed certificate | Transaction memory only | Recover and validate using issuer public key |
| Issuer master key | Yes | Never | No access, no derivation, no storage |
| ARQC | Cryptographic transaction output from card | Transient only | Parse and forward to Level 3 |
| ARPC | Cryptographic host response from issuer path | Transient only | Pass to card using CDOL2 or EXTERNAL AUTHENTICATE as applicable |
| PIN, clear | Yes | Never | Must never be visible to kernel |
| PIN block, online encrypted | Sensitive | Kernel must not dereference or copy | Pass only as secure handle/reference if required by Level 3 API |
| Unpredictable number | Security-critical nonce | Transaction memory | Request from approved random source and include in DOL inputs |

**KRN-SEC-001 SHALL** prohibit issuer master keys, issuer derivation keys, acquirer PIN keys, BDKs, and any clear PIN from being stored in, logged by, or exposed to the kernel.

**KRN-SEC-002 SHALL** treat CAPKs as public keys requiring authenticity, integrity, versioning, expiry control, and rollback protection. CAPKs do not require confidentiality.

**KRN-SEC-003 SHALL NOT** generate ARQC, TC, AAC, or ARPC. The card returns ARQC, TC, or AAC in response to GENERATE AC. The issuer or issuer processor validates ARQC and generates ARPC.

**KRN-SEC-004 SHALL** delegate PIN capture and PIN block construction to a PCI PTS approved PED or secure PIN subsystem.

---

# 3. Interface and kernel selection

## 3.1 Contact versus contactless

Contact and contactless are not the same protocol profile. The product may share parsing, logging, configuration, and state-machine infrastructure, but it must maintain separate certified behavior for contact and contactless.

| Feature | Contact | Contactless |
|---|---|---|
| Environment selection | PSE may use `1PAY.SYS.DDF01`; direct AID selection also allowed | PPSE uses `2PAY.SYS.DDF01` |
| Kernel type | EMV contact kernel behavior under contact L2 approval | EMV contactless kernel behavior, including C-8 where certified |
| Card presence | Physical insertion | RF field card/device presentation and removal |
| UI outcome | Usually terminal application driven | Kernel outcome parameters and UI requests are central |
| CVM | Full EMV CVM list processing | Scheme/contactless/C-8 limits and mobile CDCVM behavior apply |
| Timing | Contact protocol timing | Contactless RF timing, remove-card, retry, and alternate-interface behavior apply |

**KRN-INT-001 SHALL** separate contact and contactless kernel selection in configuration.

**KRN-INT-002 SHALL NOT** treat Book C-8 as a contact kernel unless a specific licensed specification and certification approval explicitly support that use.

**KRN-INT-003 SHOULD** use Book C-8 for contactless where the product, scheme set, region, terminal class, and certification scope support C-8.

## 3.2 Application and kernel selection policy

Kernel selection is a function of:

```text
selected_interface × candidate_AID × scheme_profile × certified_kernel_set × terminal_capabilities
```

The configuration package shall include a certified mapping:

```json
{
  "interface": "contactless",
  "aid": "A0000000031010",
  "scheme": "Visa",
  "kernel_type": "c8",
  "profile_id": "VISA_CONTACTLESS_C8_REGION_001"
}
```

**KRN-INT-004 SHALL** reject a transaction if no certified kernel/profile mapping exists for the selected AID and interface.

---

# 4. Deterministic transaction state machine

## 4.1 State model

The kernel is a deterministic finite-state transducer:

```text
K = (S, E, C, δ, λ)
```

where:

| Symbol | Meaning |
|---|---|
| `S` | finite set of transaction states |
| `E` | events from API calls, APDU responses, callbacks, timeouts, card removal, host response |
| `C` | transaction context: terminal parameters, card data, TVR, TSI, AIP, AFL, CDOL, CVM result, TRM result, scheme profile |
| `δ` | transition function from `(state, event, context)` to next state |
| `λ` | output function producing APDUs, callbacks, logs, TVR/TSI mutation, host data, or outcome |

## 4.2 State list

| State ID | Name | Description |
|---|---|---|
| S0 | Idle | Kernel initialized, no transaction active |
| S1 | TransactionInitialized | Transaction parameters loaded and validated |
| S2 | ApplicationSelection | PSE/PPSE/direct AID selection and candidate selection |
| S3 | GPO | PDOL constructed, GPO APDU sent, AIP/AFL parsed |
| S4 | ReadApplicationData | AFL records read and validated |
| S5 | OfflineDataAuthentication | SDA, DDA, or CDA preparation/verification as applicable |
| S6 | ProcessingRestrictions | Version, date, AUC, country/service restriction evaluation |
| S7 | CVMProcessing | CVM list evaluation and PED callbacks where required |
| S8 | TerminalRiskManagement | Floor limit, random selection, exception file, velocity where configured |
| S9 | TerminalActionAnalysis | TAC/IAC decisioning and requested cryptogram selection |
| S10 | GenerateAC1 | First GENERATE AC, CID/AC/ATC/IAD parsing, CDA verification if requested |
| S11 | OnlineProcessing | Online authorization request and host response collection through Level 3 |
| S12 | IssuerAuthentication | ARPC or issuer authentication handling where applicable |
| S13 | IssuerScriptBeforeFinalAC | Issuer Script Template 1 processing before final GENERATE AC where applicable |
| S14 | GenerateAC2 | Second GENERATE AC where required |
| S15 | IssuerScriptAfterFinalAC | Issuer Script Template 2 processing after final GENERATE AC where applicable |
| S16 | Complete | Final outcome returned, transaction context sealed for logging then reset |
| SE | Error | Fatal or unrecoverable failure |

## 4.3 Transition principles

**KRN-FSM-001 SHALL** implement the full transition table as a machine-readable artifact with RFC 4180 valid CSV or JSON.

**KRN-FSM-002 SHALL** distinguish fatal protocol errors from risk conditions. A missing mandatory tag may be fatal in one state and TVR-mediated in another only if the licensed standard permits that behavior.

**KRN-FSM-003 SHALL** preserve enough context to replay a transaction deterministically for certification debugging, excluding clear PIN and excluded sensitive data.

**KRN-FSM-004 SHALL** process card removal, APDU timeout, host timeout, and callback failure through explicitly documented transitions.

## 4.4 Transition table excerpt

| Current | Event | Guard | Next | Action |
|---|---|---|---|---|
| S0 | `krn_set_transaction_params` | valid params and valid config | S1 | Initialize context, clear TVR/TSI, store params |
| S1 | card detected on contact | interface allowed | S2 | Begin contact application selection |
| S1 | card/device detected contactless | interface allowed | S2 | Begin PPSE Entry Point processing |
| S2 | PSE selected | contact and `1PAY.SYS.DDF01` selected | S2 | Build candidate list |
| S2 | PPSE selected | contactless and `2PAY.SYS.DDF01` selected | S2 | Build contactless candidate list |
| S2 | direct AID selected | AID/profile certified | S3 | Build PDOL for selected application |
| S3 | GPO response parsed | valid AIP and AFL or valid response template | S4 | Read AFL records |
| S4 | records complete | mandatory data available | S5 | Run ODA or mark ODA not performed as defined by AIP/profile |
| S5 | ODA complete | result recorded | S6 | Set TSI/TVR as applicable |
| S6 | restrictions evaluated | TVR updated | S7 | Evaluate CVM |
| S7 | CVM evaluated | result recorded | S8 | Perform TRM |
| S8 | TRM evaluated | result recorded | S9 | Run TAA |
| S9 | TAA complete | requested AC selected | S10 | Issue first GENERATE AC |
| S10 | CID = ARQC | online capable | S11 | Build online data and call Level 3 |
| S10 | CID = TC | no online required | S16 | Offline approval outcome |
| S10 | CID = AAC | none | S16 | Offline decline outcome |
| S11 | host response received | online approval/decline available | S12 | Process issuer authentication data |
| S12 | issuer authentication complete | scripts before final AC present | S13 | Execute script template 1 |
| S13 | script phase complete | final AC required | S14 | Issue second GENERATE AC |
| S14 | CID = TC | none | S15 or S16 | Online approval outcome after post-final scripts |
| S14 | CID = AAC | none | S15 or S16 | Online decline outcome after post-final scripts |

---

# 5. EMV data object model

## 5.1 TLV and DOL parsing

The kernel shall implement a strict BER-TLV parser with bounded recursion, maximum length checks, canonical error reporting, and deterministic handling of duplicate tags according to the licensed specification and scheme profile.

A **Data Object List** is not a constructed BER-TLV template. A DOL is a value containing a sequence of tag-length references. PDOL, CDOL1, CDOL2, DDOL, and TDOL shall be parsed as DOL structures and used to construct concatenated data fields in the exact order specified by the card or profile.

**KRN-TLV-001 SHALL** parse primitive and constructed BER-TLV objects according to EMV and ISO/IEC 7816-4 rules.

**KRN-TLV-002 SHALL** parse DOLs as tag-length sequences, not as constructed TLV templates.

**KRN-TLV-003 SHALL** reject malformed tags, unsupported indefinite length encoding, lengths exceeding configured maxima, truncated values, or invalid nested templates.

**KRN-DOL-001 SHALL** construct PDOL, CDOL1, CDOL2, DDOL, and TDOL data by resolving each requested tag from the terminal/card/kernel context and appending the exact requested length.

**KRN-DOL-002 SHALL** use zero padding or profile-defined defaults only where permitted by EMV and scheme rules.

## 5.2 Minimum common data objects

This table is not a substitute for the full EMV and scheme data dictionary. It lists the minimum objects that the kernel must recognize for common contact and contactless flows.

| Tag | Name | Type | Source | Core use |
|---|---|---|---|---|
| 4F | Application Identifier | Primitive TLV | Card | Candidate and selected application |
| 50 | Application Label | Primitive TLV | Card | UI display where allowed |
| 57 | Track 2 Equivalent Data | Primitive TLV | Card | Host authorization data, masked in logs |
| 5A | PAN | Primitive TLV | Card | Host authorization data, masked in logs |
| 5F20 | Cardholder Name | Primitive TLV | Card | Optional UI/receipt subject to policy |
| 5F24 | Application Expiration Date | Primitive TLV | Card | Processing restrictions |
| 5F25 | Application Effective Date | Primitive TLV | Card | Processing restrictions |
| 5F28 | Issuer Country Code | Primitive TLV | Card | Processing restrictions |
| 5F2A | Transaction Currency Code | Primitive TLV | Terminal | CDOL and authorization data |
| 5F34 | Application PAN Sequence Number | Primitive TLV | Card | Host authorization data |
| 61 | Application Template | Constructed TLV | Card | PSE/PPSE directory entry |
| 6F | FCI Template | Constructed TLV | Card | SELECT response |
| 70 | Record Template | Constructed TLV | Card | READ RECORD response |
| 71 | Issuer Script Template 1 | Constructed TLV | Issuer via host | Script before final AC, where applicable |
| 72 | Issuer Script Template 2 | Constructed TLV | Issuer via host | Script after final AC, where applicable |
| 77 | Response Message Template Format 2 | Constructed TLV | Card | GPO or GENERATE AC response |
| 80 | Response Message Template Format 1 or primitive data, context-defined | Primitive/contextual | Card | GPO or cryptogram response by context |
| 82 | AIP | Primitive TLV | Card | Capability flags |
| 84 | DF Name | Primitive TLV | Card | SELECT response |
| 8A | Authorization Response Code | Primitive TLV | Host via L3 | CDOL2 and final decision |
| 8C | CDOL1 | DOL value | Card | First GENERATE AC input definition |
| 8D | CDOL2 | DOL value | Card | Second GENERATE AC input definition |
| 8E | CVM List | Primitive value with CVM rule encoding | Card | CVM processing |
| 8F | CA Public Key Index | Primitive TLV | Card | CAPK selection |
| 90 | Issuer Public Key Certificate | Primitive TLV | Card | ODA |
| 91 | Issuer Authentication Data | Primitive TLV | Host via L3 | Issuer authentication / ARPC data |
| 92 | Issuer Public Key Remainder | Primitive TLV | Card | ODA |
| 93 | Signed Static Application Data | Primitive TLV | Card | SDA |
| 94 | AFL | Primitive TLV | Card | READ RECORD plan |
| 95 | TVR | Primitive TLV | Kernel | Risk and verification result bitmap |
| 9A | Transaction Date | Primitive TLV | Terminal | CDOL and restrictions |
| 9B | TSI | Primitive TLV | Kernel | Transaction status bitmap |
| 9C | Transaction Type | Primitive TLV | Terminal | CDOL and restrictions |
| 9F02 | Amount Authorized | Primitive TLV | Terminal | CDOL and risk |
| 9F03 | Amount Other | Primitive TLV | Terminal | Cashback or other amount |
| 9F07 | Application Usage Control | Primitive TLV | Card | Processing restrictions |
| 9F08 or 9F09 | Application Version Number | Primitive TLV | Card/terminal context | Version comparison, profile-defined |
| 9F10 | Issuer Application Data | Primitive TLV | Card | Host authorization data |
| 9F1A | Terminal Country Code | Primitive TLV | Terminal | CDOL and restrictions |
| 9F1E | Interface Device Serial Number | Primitive TLV | Terminal | Optional host/support data |
| 9F26 | Application Cryptogram | Primitive TLV | Card | ARQC, TC, or AAC value |
| 9F27 | CID | Primitive TLV | Card | Cryptogram type decode |
| 9F32 | Issuer Public Key Exponent | Primitive TLV | Card | ODA |
| 9F33 | Terminal Capabilities | Primitive TLV | Terminal | CVM and capability processing |
| 9F34 | CVM Results | Primitive TLV | Kernel | CVM result for host and CDOL |
| 9F35 | Terminal Type | Primitive TLV | Terminal | Risk/profile logic |
| 9F36 | ATC | Primitive TLV | Card | Host data and risk logic |
| 9F37 | Unpredictable Number | Primitive TLV | Terminal | DDA, CDA, and cryptogram input |
| 9F40 | Additional Terminal Capabilities | Primitive TLV | Terminal | Capability expression |
| 9F46 | ICC Public Key Certificate | Primitive TLV | Card | DDA/CDA ODA |
| 9F47 | ICC Public Key Exponent | Primitive TLV | Card | DDA/CDA ODA |
| 9F48 | ICC Public Key Remainder | Primitive TLV | Card | DDA/CDA ODA |
| 9F49 | DDOL | DOL value | Card/profile | DDA input definition |
| 9F4A | Static Data Authentication Tag List | Primitive TLV | Card | SDA input definition |
| 9F4B | Signed Dynamic Application Data | Primitive TLV | Card | DDA/CDA signature object |
| 9F4C | ICC Dynamic Number | Primitive TLV | Card/recovered data | DDA/CDA recovered dynamic data |
| 9F4E | Merchant Name and Location | Primitive TLV | Terminal | Optional host/card data |
| 9F66 | TTQ | Primitive TLV | Terminal | Contactless capability flags, profile-defined |
| 9F6C | CTQ | Primitive TLV | Card | Contactless/mobile CVM behavior, profile-defined |
| 9F6E | Form Factor Indicator | Primitive TLV | Card/device | Mobile/contactless analytics/profile logic |
| 9F7C | Customer Exclusive Data | Primitive TLV | Terminal/card context | Scheme/profile-defined |

**KRN-TLV-004 SHALL** maintain a machine-readable TLV catalogue with columns: tag, name, type, length rule, source, interface applicability, scheme applicability, presence rule, sensitive-data classification, and test IDs.

**KRN-TLV-005 SHALL** mark scheme-specific, proprietary, and RFU tags as PROFILE-DEFINED and shall not assign invented semantics.

**KRN-TLV-006 SHALL** admit card-originated AFL record TLVs only from direct primitive Template `70` children and shall reject terminal-owned or kernel-owned tags without partially updating the transaction data store.

---

# 6. TVR, TSI, CID, and CVM result bitmaps

## 6.1 Bit numbering convention

This document uses both EMV-style byte/bit numbering and zero-based code masks.

| EMV table notation | Code notation |
|---|---|
| Byte 1, bit 8 | `tvr[0] & 0x80` |
| Byte 1, bit 1 | `tvr[0] & 0x01` |
| Byte 5, bit 8 | `tvr[4] & 0x80` |

**KRN-BIT-001 SHALL** define all bitmaps using symbolic constants and one canonical mapping file. Implementation code SHALL NOT use unexplained raw bitmap literals.

## 6.2 Terminal Verification Results, TVR

The TVR is five bytes. The following table gives the common EMV Book 3 TVR conditions used by this specification. The implementation shall validate this table against the licensed EMV baseline before certification freeze.

| Byte | Bit | Mask | Condition | Set by |
|---:|---:|---:|---|---|
| 1 | 8 | 0x80 | Offline data authentication was not performed | ODA |
| 1 | 7 | 0x40 | SDA failed | ODA |
| 1 | 6 | 0x20 | ICC data missing | TLV/ODA |
| 1 | 5 | 0x10 | Card appears on terminal exception file | TRM |
| 1 | 4 | 0x08 | DDA failed | ODA |
| 1 | 3 | 0x04 | CDA failed | ODA |
| 1 | 2 | 0x02 | SDA selected | ODA |
| 1 | 1 | 0x01 | RFU | Never set unless licensed spec/profile defines |
| 2 | 8 | 0x80 | ICC and terminal have different application versions | Restrictions |
| 2 | 7 | 0x40 | Expired application | Restrictions |
| 2 | 6 | 0x20 | Application not yet effective | Restrictions |
| 2 | 5 | 0x10 | Requested service not allowed for card product | Restrictions |
| 2 | 4 | 0x08 | New card | Restrictions/card data |
| 2 | 3 | 0x04 | RFU | Never set unless licensed spec/profile defines |
| 2 | 2 | 0x02 | RFU | Never set unless licensed spec/profile defines |
| 2 | 1 | 0x01 | RFU | Never set unless licensed spec/profile defines |
| 3 | 8 | 0x80 | Cardholder verification was not successful | CVM |
| 3 | 7 | 0x40 | Unrecognized CVM | CVM |
| 3 | 6 | 0x20 | PIN try limit exceeded | CVM/PED/VERIFY |
| 3 | 5 | 0x10 | PIN entry required and PIN pad not present or not working | CVM/PED |
| 3 | 4 | 0x08 | PIN entry required, PIN pad present, but PIN was not entered | CVM/PED |
| 3 | 3 | 0x04 | Online PIN entered | CVM/PED |
| 3 | 2 | 0x02 | RFU | Never set unless licensed spec/profile defines |
| 3 | 1 | 0x01 | RFU | Never set unless licensed spec/profile defines |
| 4 | 8 | 0x80 | Transaction exceeds floor limit | TRM |
| 4 | 7 | 0x40 | Lower consecutive offline limit exceeded | TRM |
| 4 | 6 | 0x20 | Upper consecutive offline limit exceeded | TRM |
| 4 | 5 | 0x10 | Transaction selected randomly for online processing | TRM |
| 4 | 4 | 0x08 | Merchant forced transaction online | TRM/L3 profile |
| 4 | 3 | 0x04 | RFU | Never set unless licensed spec/profile defines |
| 4 | 2 | 0x02 | RFU | Never set unless licensed spec/profile defines |
| 4 | 1 | 0x01 | RFU | Never set unless licensed spec/profile defines |
| 5 | 8 | 0x80 | Default TDOL used | DOL construction |
| 5 | 7 | 0x40 | Issuer authentication failed | Issuer auth |
| 5 | 6 | 0x20 | Script processing failed before final GENERATE AC | Script processor |
| 5 | 5 | 0x10 | Script processing failed after final GENERATE AC | Script processor |
| 5 | 4 | 0x08 | RFU | Never set unless licensed spec/profile defines |
| 5 | 3 | 0x04 | RFU | Never set unless licensed spec/profile defines |
| 5 | 2 | 0x02 | RFU | Never set unless licensed spec/profile defines |
| 5 | 1 | 0x01 | RFU | Never set unless licensed spec/profile defines |

**KRN-TVR-001 SHALL** clear TVR to `00 00 00 00 00` before each transaction.

**KRN-TVR-002 SHALL** set only symbolic TVR constants mapped to byte, bit, and mask in the approved bitmap mapping file.

**KRN-TVR-003 SHALL NOT** invent TVR bits for conditions such as currency mismatch or non-standard profile checks. Such conditions shall be represented by the licensed EMV restriction semantics, scheme rules, or terminal decision policy.

## 6.3 Transaction Status Indicator, TSI

The TSI is two bytes. Common EMV conditions are:

| Byte | Bit | Mask | Condition | Set by |
|---:|---:|---:|---|---|
| 1 | 8 | 0x80 | Offline data authentication was performed | ODA |
| 1 | 7 | 0x40 | Cardholder verification was performed | CVM |
| 1 | 6 | 0x20 | Card risk management was performed | Card/kernel based on AIP/profile |
| 1 | 5 | 0x10 | Issuer authentication was performed | Issuer auth |
| 1 | 4 | 0x08 | Terminal risk management was performed | TRM |
| 1 | 3 | 0x04 | Script processing was performed | Script processor |
| 1 | 2 | 0x02 | RFU | Never set unless licensed spec/profile defines |
| 1 | 1 | 0x01 | RFU | Never set unless licensed spec/profile defines |
| 2 | 8-1 | varies | RFU | Never set unless licensed spec/profile defines |

**KRN-TSI-001 SHALL** clear TSI to `00 00` before each transaction.

**KRN-TSI-002 SHALL** set TSI bits only after the corresponding function has actually been performed.

## 6.4 Cryptogram Information Data, CID

The kernel shall decode cryptogram type from the high two bits of tag `9F27`.

| CID mask | Cryptogram type | Meaning |
|---:|---|---|
| `CID & 0xC0 == 0x00` | AAC | Application Authentication Cryptogram, decline |
| `CID & 0xC0 == 0x40` | TC | Transaction Certificate, approval |
| `CID & 0xC0 == 0x80` | ARQC | Authorization Request Cryptogram, go online |
| `CID & 0xC0 == 0xC0` | AAR or RFU/profile-defined referral | LICENSED-SPEC-DEFINED |

```c
static inline krn_cryptogram_type_t krn_decode_cid(uint8_t cid) {
    switch (cid & 0xC0) {
        case 0x00: return KRN_CRYPTOGRAM_AAC;
        case 0x40: return KRN_CRYPTOGRAM_TC;
        case 0x80: return KRN_CRYPTOGRAM_ARQC;
        case 0xC0: return KRN_CRYPTOGRAM_AAR_OR_PROFILE_DEFINED;
        default:   return KRN_CRYPTOGRAM_INVALID;
    }
}
```

**KRN-CID-001 SHALL** decode CID by masking `0xC0`, not by testing unmasked equality of the whole byte.

**KRN-CID-002 SHALL** preserve non-type CID bits for trace logging and scheme/profile handling, but SHALL NOT use them to change cryptogram type classification unless the licensed specification/profile requires it.

## 6.5 CVM Results

Tag `9F34` shall be produced according to EMV CVM result encoding. Exact method, condition, and result codes shall be mapped from the licensed EMV baseline and scheme profile. The kernel shall not invent method codes such as “CDCVM = 05” unless that mapping is explicitly defined by the relevant contactless profile.

**KRN-CVMRES-001 SHALL** store CVM Results as a 3-byte object with method, condition, and result semantics validated against EMV and scheme rules.

---

# 7. APDU command specification

## 7.1 General APDU rules

**KRN-APDU-001 SHALL** construct all APDUs according to ISO/IEC 7816-4 and EMV command-specific rules.

**KRN-APDU-002 SHALL** handle APDU response status words by command and state, not by a single global success/failure rule.

**KRN-APDU-003 SHALL** implement at least the following status-word categories where applicable:

| SW1/SW2 | Category | Required handling |
|---|---|---|
| `90 00` | Success | Parse response according to command/state |
| `61 xx` | More data available | Issue GET RESPONSE where applicable or handle per interface/profile |
| `6C xx` | Correct length indicated | Retry once with indicated Le where permitted |
| `63 Cx` | Warning, counter provided | VERIFY/PIN handling, x = tries remaining |
| `62 83` | Selected file invalidated or warning, context-dependent | Handle per SELECT/profile rules |
| `69 85` | Conditions of use not satisfied | State-specific failure or TVR-mediated path |
| `6A 82` | File or application not found | Candidate selection fallback or no common AID |
| `6A 83` | Record not found | AFL/record handling per EMV rules |
| Other | Error or profile-defined | Transition according to state-specific table |

## 7.2 SELECT

### 7.2.1 Contact PSE SELECT

| Field | Value |
|---|---|
| CLA | `00` |
| INS | `A4` |
| P1 | `04` |
| P2 | `00` or profile-defined |
| Data | ASCII `1PAY.SYS.DDF01`, hex `315041592E5359532E4444463031` |
| Le | `00` or profile-defined |

### 7.2.2 Contactless PPSE SELECT

| Field | Value |
|---|---|
| CLA | `00` |
| INS | `A4` |
| P1 | `04` |
| P2 | `00` or profile-defined |
| Data | ASCII `2PAY.SYS.DDF01`, hex `325041592E5359532E4444463031` |
| Le | `00` or profile-defined |

### 7.2.3 Direct AID SELECT

| Field | Value |
|---|---|
| CLA | `00` |
| INS | `A4` |
| P1 | `04` |
| P2 | `00` or profile-defined |
| Data | selected AID |
| Le | `00` or profile-defined |

**KRN-SEL-001 SHALL** use `1PAY.SYS.DDF01` for contact PSE selection where PSE selection is attempted.

**KRN-SEL-002 SHALL** use `2PAY.SYS.DDF01` for contactless PPSE selection.

**KRN-SEL-003 SHALL** support direct AID selection when PSE/PPSE is absent, unsupported, or profile rules require direct selection.

## 7.3 GET PROCESSING OPTIONS

GPO command data shall be encoded as tag `83` followed by the PDOL data value. If PDOL is absent or empty, command data shall use the profile-permitted empty PDOL form.

| Field | Value |
|---|---|
| CLA | `80` |
| INS | `A8` |
| P1 | `00` |
| P2 | `00` |
| Data | `83 || L || PDOL_values` |
| Le | profile-defined, often `00` |

GPO response may be:

| Template | Meaning |
|---|---|
| `80` | Response Message Template Format 1, containing AIP and AFL in compact form |
| `77` | Response Message Template Format 2, containing TLV objects such as `82` and `94` |

**KRN-GPO-001 SHALL** parse both valid GPO response formats permitted by the active profile.

**KRN-GPO-002 SHALL** extract AIP and AFL or transition according to the licensed failure rules if absent or malformed.

## 7.4 READ RECORD

| Field | Value |
|---|---|
| CLA | `00` |
| INS | `B2` |
| P1 | record number |
| P2 | `(SFI << 3) | 0x04` |
| Le | `00` or profile-defined |

**KRN-RR-001 SHALL** validate SFI range and record number range before constructing READ RECORD.

**KRN-RR-002 SHALL** construct P2 exactly as `(SFI << 3) | 0x04` for standard record reading.

**KRN-RR-003 SHALL** parse returned record templates and update the card data store without logging sensitive values unmasked.

**KRN-RR-004 SHALL** reject inconsistent or malformed cardholder PAN data between tags `5A` and `57` without partially updating the card data store.

## 7.5 INTERNAL AUTHENTICATE

INTERNAL AUTHENTICATE is used for DDA where supported and required. It is not used for SDA.

| Field | Value |
|---|---|
| CLA | `00` |
| INS | `88` |
| P1 | `00` |
| P2 | `00` |
| Data | DDOL values |
| Le | profile-defined |

The response contains signed dynamic application data, commonly represented by tag `9F4B` where the response is TLV encoded. Recovered signed data may include dynamic data such as the ICC Dynamic Number, tag `9F4C`, according to EMV rules.

**KRN-DDA-001 SHALL** use INTERNAL AUTHENTICATE only for DDA where the AIP, card data, and profile require or allow it.

**KRN-DDA-002 SHALL** verify signed dynamic application data using the recovered ICC public key.

## 7.6 VERIFY for offline PIN

Offline PIN handling is split into two distinct methods.

| Offline PIN method | VERIFY command data | P2 handling |
|---|---|---|
| Plaintext offline PIN | PED-produced EMV offline plaintext PIN block | EMV-defined plaintext PIN reference, commonly `0x80`, profile-verified |
| Enciphered offline PIN | PED/secure module-produced enciphered PIN block using ICC public key data | EMV-defined enciphered PIN reference, commonly `0x88`, profile-verified |

**KRN-PIN-001 SHALL** distinguish plaintext offline PIN, enciphered offline PIN, and online PIN in the CVM engine and API.

**KRN-PIN-002 SHALL NOT** construct clear PIN values or expose clear PIN to kernel memory.

**KRN-PIN-003 SHALL** delegate PIN block construction to the PCI PTS PED or secure PIN module.

**KRN-PIN-004 SHALL** interpret `63 Cx` from VERIFY as PIN verification warning with tries remaining and update TVR/CVM results accordingly.

## 7.7 GENERATE AC

The kernel sends GENERATE AC to request a cryptogram from the card. The card generates the cryptogram.

| Field | Value |
|---|---|
| CLA | `80` |
| INS | `AE` |
| P1 | Reference Control Parameter containing requested cryptogram type and profile-defined bits |
| P2 | `00` unless profile-defined |
| Data | CDOL1 or CDOL2 values |
| Le | profile-defined, often `00` |

### 7.7.1 GENERATE AC request type encoding

The high-order cryptogram request bits shall be represented by constants:

| Request | P1 cryptogram request bits |
|---|---:|
| AAC requested | `0x00` |
| TC requested | `0x40` |
| ARQC requested | `0x80` |
| Reserved/referral/profile-defined | `0xC0`, only if licensed spec/profile permits |

CDA-related request bits and all lower-order P1 bits are LICENSED-SPEC-DEFINED and must be resolved from the applicable EMV and scheme profile. They shall not be inferred.

```c
typedef enum {
    KRN_AC_REQ_AAC  = 0x00,
    KRN_AC_REQ_TC   = 0x40,
    KRN_AC_REQ_ARQC = 0x80
} krn_ac_request_t;

uint8_t krn_build_generate_ac_p1(krn_ac_request_t req, uint8_t profile_flags) {
    return ((uint8_t)req) | (profile_flags & 0x3F);
}
```

**KRN-GAC-001 SHALL** construct CDOL1 and CDOL2 data exactly from the active DOL definition.

**KRN-GAC-002 SHALL** encode requested cryptogram type using `0x00`, `0x40`, or `0x80` request bits, plus only licensed/profile-defined lower-bit flags.

**KRN-GAC-003 SHALL NOT** use `0x80` as a “first GENERATE AC flag.”

**KRN-GAC-004 SHALL** parse returned CID by `CID & 0xC0` and shall parse AC, ATC, IAD, and any response template data according to EMV/profile rules.

## 7.8 EXTERNAL AUTHENTICATE and issuer authentication

EXTERNAL AUTHENTICATE may be required depending on AIP, issuer authentication support, and host response. The kernel shall support it where required by the card/profile.

| Field | Value |
|---|---|
| CLA | `00` |
| INS | `82` |
| P1 | `00` |
| P2 | `00` |
| Data | Issuer authentication data / ARPC as profile-defined |
| Le | absent or profile-defined |

**KRN-IAUTH-001 SHALL** process tag `91` Issuer Authentication Data according to the licensed specification and profile.

**KRN-IAUTH-002 SHALL** set TSI issuer authentication performed only when issuer authentication has actually been performed.

**KRN-IAUTH-003 SHALL** set TVR issuer authentication failed if issuer authentication was attempted and failed.

---

# 8. Offline Data Authentication

## 8.1 ODA method selection

ODA method selection is based on AIP, available records, scheme profile, terminal capabilities, and contact/contactless mode.

| Method | Summary | Key commands/data |
|---|---|---|
| SDA | Static signature verification over static card data | CAPK, issuer public key certificate, signed static application data |
| DDA | Dynamic signature generated by card in response to INTERNAL AUTHENTICATE | CAPK, issuer public key, ICC public key, DDOL, `9F4B` |
| CDA | Dynamic authentication combined with application cryptogram generation | ICC public key, GENERATE AC response, signed dynamic data and cryptogram linkage |

**KRN-ODA-001 SHALL** select ODA method according to AIP and profile. If ODA is not performed when expected or required, TVR shall be set according to EMV rules.

## 8.2 CAPK handling

CAPK lookup key:

```text
RID + CA Public Key Index
```

Each CAPK record shall contain at least:

| Field | Required |
|---|---:|
| RID | Yes |
| Key index | Yes |
| Algorithm identifier, where applicable | Yes |
| Modulus | Yes |
| Exponent | Yes |
| Expiry | Yes |
| Hash/checksum or signed configuration integrity proof | Yes |
| Source/version | Yes |

**KRN-CAPK-001 SHALL** reject CAPKs whose signed configuration integrity cannot be verified.

**KRN-CAPK-002 SHALL** treat expired CAPKs as unavailable unless a lab-approved test profile explicitly requires expiry simulation.

## 8.3 Certificate recovery and verification

**KRN-ODA-002 SHALL** recover and verify issuer public key certificate data using the selected CAPK.

**KRN-ODA-003 SHALL** reconstruct issuer public key material including remainders where applicable.

**KRN-ODA-004 SHALL** recover and verify ICC public key certificate data using the recovered issuer public key where DDA/CDA requires it.

**KRN-ODA-005 SHALL** verify SDA signed static application data using the recovered issuer public key and the EMV-defined static authentication data set.

**KRN-ODA-006 SHALL** verify DDA signed dynamic application data using the recovered ICC public key.

**KRN-ODA-007 SHALL** verify CDA after first GENERATE AC where CDA is requested/supported, including the signed dynamic data relation to the application cryptogram according to the licensed specification.

## 8.4 ODA test vectors

An ODA vector is executable only if it contains complete cryptographic input and expected output. Placeholder strings such as `...` are prohibited in certification vectors.

Required vector fields:

| Field | SDA | DDA | CDA |
|---|---:|---:|---:|
| CAPK RID, index, exponent, complete modulus | Yes | Yes | Yes |
| CAPK expiry and integrity value | Yes | Yes | Yes |
| Issuer public key certificate | Yes | Yes | Yes |
| Issuer public key remainder, if applicable | Yes | Yes | Yes |
| Issuer public key exponent | Yes | Yes | Yes |
| ICC public key certificate | No | Yes | Yes |
| ICC public key remainder, if applicable | No | Yes | Yes |
| ICC public key exponent | No | Yes | Yes |
| Signed static application data | Yes | No | No |
| Static Data Authentication Tag List, where present | Yes | No | No |
| DDOL input | No | Yes | Profile-defined |
| INTERNAL AUTHENTICATE response | No | Yes | No |
| GENERATE AC response and signed dynamic data | No | No | Yes |
| Expected recovered data fields | Yes | Yes | Yes |
| Expected TVR/TSI after ODA | Yes | Yes | Yes |

**KRN-ODATV-001 SHALL** reject ODA certification test vectors that contain placeholders, truncated cryptographic material, non-hex characters, or missing expected outputs.

---

# 9. Processing restrictions

Processing restrictions shall update TVR but shall not automatically decline unless TAA and scheme profile produce that result.

## 9.1 Required checks

| Check | Source data | Result on failure |
|---|---|---|
| Application version compatibility | Application version number from card and terminal/profile version | Set TVR Byte 2 Bit 8 |
| Application expired | Application expiration date and transaction date | Set TVR Byte 2 Bit 7 |
| Application not yet effective | Application effective date and transaction date | Set TVR Byte 2 Bit 6 |
| Requested service not allowed | AUC, transaction type, domestic/international/cash/goods/service profile | Set TVR Byte 2 Bit 5 |
| New card, where applicable | Card data/profile | Set TVR Byte 2 Bit 4 where EMV/profile permits |

**KRN-REST-001 SHALL** evaluate processing restrictions in the order required by EMV and scheme profile.

**KRN-REST-002 SHALL NOT** create non-standard TVR bits for currency mismatch or service mismatch. The implementation shall express such conditions using the EMV-defined AUC/service/version/date conditions or profile-defined terminal decision inputs.

---

# 10. Cardholder Verification Method processing

## 10.1 CVM rule processing

The CVM engine shall parse the CVM List from tag `8E` and evaluate rules in card-defined priority order, subject to terminal capabilities, transaction amount, amount X/Y thresholds, country/currency rules, and scheme/contactless limits.

The CVM engine shall support at least:

| CVM category | Notes |
|---|---|
| Plaintext offline PIN | Uses PED and VERIFY plaintext offline PIN path |
| Enciphered offline PIN | Uses PED/secure module and ICC public key data |
| Online PIN | PED returns secure encrypted PIN reference for host path |
| Signature | If scheme/acquirer/region permits |
| No CVM required | Only if limits and profile permit |
| CDCVM/mobile-device CVM | Contactless/profile-defined, not assigned an invented generic EMV code |
| Fail CVM processing | According to EMV CVM list rules |

**KRN-CVM-001 SHALL** implement CVM condition-code evaluation from the licensed EMV baseline.

**KRN-CVM-002 SHALL** set `9F34` CVM Results according to EMV encoding.

**KRN-CVM-003 SHALL** update TVR Byte 3 only using EMV-defined CVM failure conditions.

**KRN-CVM-004 SHALL NOT** treat CDCVM as a universal method code unless the active contactless profile explicitly defines that mapping.

## 10.2 PIN API boundary

```c
typedef enum {
    KRN_PIN_METHOD_OFFLINE_PLAINTEXT,
    KRN_PIN_METHOD_OFFLINE_ENCIPHERED,
    KRN_PIN_METHOD_ONLINE
} krn_pin_method_t;

typedef enum {
    KRN_PIN_STATUS_SUCCESS,
    KRN_PIN_STATUS_FAILURE,
    KRN_PIN_STATUS_CANCELLED,
    KRN_PIN_STATUS_BYPASSED,
    KRN_PIN_STATUS_TIMEOUT,
    KRN_PIN_STATUS_TRY_LIMIT_EXCEEDED,
    KRN_PIN_STATUS_PED_UNAVAILABLE,
    KRN_PIN_STATUS_PED_ERROR
} krn_pin_status_t;

typedef struct {
    krn_pin_method_t method;
    krn_pin_status_t status;
    uint8_t try_remain;
    krn_secure_handle_t secure_pin_data_handle;
    size_t secure_pin_data_len;
} krn_pin_result_t;
```

**KRN-PINAPI-001 SHALL** return only status and secure handles from the PED. The kernel SHALL NOT read clear PIN data.

**KRN-PINAPI-002 SHALL** not copy online PIN encrypted blocks into general kernel memory. If Level 3 requires the value, the kernel shall pass a secure handle/reference through the approved interface.

---

# 11. Terminal Risk Management

## 11.1 Required checks

TRM shall evaluate:

| Check | TVR result |
|---|---|
| Exception file match | TVR Byte 1 Bit 5 |
| Floor limit exceeded | TVR Byte 4 Bit 8 |
| Lower consecutive offline limit exceeded | TVR Byte 4 Bit 7 |
| Upper consecutive offline limit exceeded | TVR Byte 4 Bit 6 |
| Random online selection | TVR Byte 4 Bit 5 |
| Merchant forced online | TVR Byte 4 Bit 4 |

**KRN-TRM-001 SHALL** implement floor-limit checking per profile and transaction type.

**KRN-TRM-002 SHALL** implement random transaction selection only according to EMV/profile rules. The algorithm and parameters shall be certified as part of the profile.

**KRN-TRM-003 SHALL** maintain offline counters only in non-volatile storage where the active scheme/profile requires terminal-maintained counters.

**KRN-TRM-004 SHALL** set TSI terminal risk management performed when TRM has executed.

## 11.2 Random selection

Previous draft algorithms that used ad hoc expressions such as `(ATC + UN) & 0xFFFF` are not normative. Random selection shall use the EMV-defined or scheme-defined random selection method, thresholds, target percentage, maximum target percentage, and biased random selection parameters from the certified profile.

---

# 12. Terminal Action Analysis

## 12.1 Inputs

TAA input set:

| Input | Source |
|---|---|
| TVR | Kernel accumulated state |
| TAC-Denial, TAC-Online, TAC-Default | Terminal/profile configuration |
| IAC-Denial, IAC-Online, IAC-Default | Card data or profile as applicable |
| Terminal online capability | Terminal profile and runtime communications state |
| Offline approval allowed | Scheme/application/profile |
| Default action policy | Scheme/application/profile, constrained by EMV rules |

## 12.2 Decision policy

The following decision table is normative at product level but must be validated against the licensed EMV and scheme profile.

| Case | Condition | Requested cryptogram |
|---|---|---|
| Denial condition | `(TVR & (TAC-Denial OR IAC-Denial)) != 0` | AAC |
| Online condition, online available | no denial and online-capable and `(TVR & (TAC-Online OR IAC-Online)) != 0` | ARQC |
| Online condition, online unavailable | online condition true but terminal cannot go online | Evaluate default path under profile. Usually AAC unless offline approval fallback is explicitly allowed. |
| Default condition, offline-only or online unavailable | `(TVR & (TAC-Default OR IAC-Default)) != 0` under unable-to-go-online context | AAC or TC only as profile permits |
| No adverse condition, offline approval allowed | profile permits offline approval | TC |
| No adverse condition, online required by profile | profile requires online | ARQC |
| Fallback or unsupported state | profile prohibits completion | AAC or terminate, according to licensed rules |

**KRN-TAA-001 SHALL** evaluate denial before online approval requests.

**KRN-TAA-002 SHALL** include IAC values in TAA whenever available or required by the application/profile.

**KRN-TAA-003 SHALL NOT** allow an unconstrained configuration field such as `default_cryptogram` to override EMV or scheme rules.

**KRN-TAA-004 SHALL** log the TAA inputs and selected requested cryptogram in masked trace logs.

---

# 13. GENERATE AC and online processing

## 13.1 First GENERATE AC

**KRN-GAC1-001 SHALL** build CDOL1 from tag `8C` where present, or from profile-defined defaults where permitted.

**KRN-GAC1-002 SHALL** include the unpredictable number, TVR, transaction amount, date, type, terminal country, CVM results, and other requested data exactly as CDOL1 requires.

**KRN-GAC1-003 SHALL** request AAC, TC, or ARQC according to TAA.

**KRN-GAC1-004 SHALL** parse response format 1 or 2 as permitted by the active profile.

**KRN-GAC1-005 SHALL** if CDA was requested, verify CDA before accepting the returned cryptogram outcome.

## 13.2 Online request handoff

If first GENERATE AC returns ARQC, the kernel shall produce an online authorization data package for Level 3. The Level 3 application owns host message formatting.

Minimum ICC data package subject to scheme/acquirer profile:

| Object | Purpose |
|---|---|
| `9F26` AC/ARQC | Issuer cryptogram validation |
| `9F27` CID | Cryptogram type/status |
| `9F10` IAD | Issuer application data |
| `9F37` UN | Cryptogram input |
| `9F36` ATC | Card transaction counter |
| `95` TVR | Terminal verification result |
| `9A` Transaction Date | Authorization data |
| `9C` Transaction Type | Authorization data |
| `9F02` Amount Authorized | Authorization data |
| `5F2A` Currency Code | Authorization data |
| `82` AIP | Card capability data |
| `9F1A` Terminal Country Code | Authorization data |
| `5A` or tokenized equivalent | PAN or token data, masked in logs |
| `57` where required | Track 2 equivalent data, never logged unmasked |

**KRN-ONL-001 SHALL** pass online authorization data to Level 3 without performing acquirer/issuer host role.

**KRN-ONL-002 SHALL** receive host response data, including authorization response code, issuer authentication data, and issuer scripts, through the Level 3 callback/API.

## 13.3 Issuer authentication and second GENERATE AC

**KRN-GAC2-001 SHALL** construct CDOL2 from card/profile data and host response data.

**KRN-GAC2-002 SHALL** include issuer authentication data or authorization response data in the form required by CDOL2/profile.

**KRN-GAC2-003 SHALL** issue second GENERATE AC where required after online authorization.

**KRN-GAC2-004 SHALL** treat final TC as approval and final AAC as decline, subject to issuer script and profile rules.

---

# 14. Issuer script processing

Issuer scripts are host-provided APDU command sequences in EMV issuer script templates.

| Template | Typical phase | Handling |
|---|---|---|
| `71` Issuer Script Template 1 | Before final GENERATE AC | Execute before final AC where required |
| `72` Issuer Script Template 2 | After final GENERATE AC | Execute after final AC where required |

**KRN-SCR-001 SHALL** validate script template structure before execution.

**KRN-SCR-002 SHALL** execute issuer script commands in the order provided.

**KRN-SCR-003 SHALL** capture SW1/SW2 for each script command.

**KRN-SCR-004 SHALL** set TVR Byte 5 Bit 6 when script processing fails before final GENERATE AC.

**KRN-SCR-005 SHALL** set TVR Byte 5 Bit 5 when script processing fails after final GENERATE AC.

**KRN-SCR-006 SHALL** report script phase and SW1/SW2 results to Level 3 for host reporting according to acquirer/scheme rules.

---

# 15. Contactless and C-8 annex

## 15.1 Contactless Entry Point

Contactless application selection shall use PPSE and Entry Point behavior according to EMV Contactless and Book C-8 where claimed.

Required behavior:

1. Detect contactless card or mobile device through Level 1.
2. SELECT PPSE `2PAY.SYS.DDF01`.
3. Parse FCI and candidate AID list.
4. Match candidate AIDs to certified terminal profiles.
5. Select the certified contactless kernel for the selected AID.
6. Apply contactless limits, terminal transaction qualifiers, and UI outcome behavior according to active profile.

**KRN-CLESS-001 SHALL** use PPSE `2PAY.SYS.DDF01` for contactless Entry Point.

**KRN-CLESS-002 SHALL** return structured contactless outcome data rather than only generic approve/decline status.

## 15.2 C-8 outcome parameter model

The C-8 outcome parameter set is LICENSED-SPEC-DEFINED. The Hyperion callback shall be able to express at least:

| Field | Description |
|---|---|
| outcome code | approved, declined, online required, try again, select next, alternate interface, terminate, or profile-defined |
| start signal | whether transaction should start/restart/prompt |
| UI request | message identifier, status, hold time, language preference as defined by profile |
| data record | data to be passed to Level 3 |
| discretionary data | profile-defined data |
| alternate interface instruction | prompt for insert/swipe/another card where permitted |

```c
typedef struct {
    uint8_t outcome_code;
    uint8_t start_signal;
    uint8_t ui_message_id;
    uint16_t hold_time_ms;
    uint8_t restart_required;
    const uint8_t *data_record;
    size_t data_record_len;
    const uint8_t *discretionary_data;
    size_t discretionary_data_len;
} krn_contactless_outcome_t;
```

**KRN-C8-001 SHALL** implement the contactless outcome callback using a structure capable of representing the licensed C-8 outcome data set.

**KRN-C8-002 SHALL NOT** reduce C-8 outcome behavior to a text message string only.

## 15.3 Contactless limits and CDCVM

The following limits shall be profile-defined and region-specific:

| Limit | Meaning |
|---|---|
| Contactless transaction limit | Above this, contactless may be disallowed or alternate interface required |
| Contactless CVM limit | Above this, CVM is required |
| Contactless floor limit | Above this, online may be required |
| CDCVM acceptance policy | Conditions under which consumer-device CVM satisfies CVM |

**KRN-CLESS-003 SHALL** evaluate contactless transaction limit, CVM limit, and floor limit using signed scheme/acquirer configuration.

**KRN-CLESS-004 SHALL** treat CDCVM as profile-defined. The kernel SHALL NOT assume that any single tag or bit universally proves CDCVM without scheme/profile validation.

## 15.4 Relay resistance

Relay resistance, distance bounding, or latency-based checks are optional unless required by the active C-8/scheme profile.

**KRN-CLESS-005 SHALL** implement relay-resistance APDUs, timing constraints, and result handling only where the licensed profile requires or certifies them.

---

# 16. Configuration model

## 16.1 Configuration package

The kernel shall load a signed configuration package. The package shall be divided into:

| Partition | Purpose |
|---|---|
| product metadata | kernel version, ABI version, profile version, issuer of config |
| terminal defaults | country, currency, terminal type, capabilities, additional capabilities |
| interface policy | contact/contactless enablement, certified kernel mappings |
| scheme profiles | AID rules, TAC/IAC, limits, CVM policy, contactless policy |
| CAPK set | RID/index keyed CAPKs with source/version/expiry |
| test/cert metadata | lab profile ID, conformance profile, supported test plan |
| signature envelope | signature, signing certificate/key ID, anti-rollback counter |

**KRN-CFG-001 SHALL** verify digital signature before using any configuration data.

**KRN-CFG-002 SHALL** reject configurations with invalid schema, unknown mandatory fields, expired CAPKs, invalid AID encoding, invalid hex strings, non-hex key material, or invalid terminal parameter lengths.

**KRN-CFG-003 SHALL** implement rollback protection using monotonic versioning or secure counters.

**KRN-CFG-004 SHALL** distinguish example profiles from certification profiles. Example profiles SHALL NOT be loadable in production build mode.

## 16.2 Scheme profiles

A scheme profile is certifiable only if all values are complete and traceable to a licensed source or lab-approved configuration.

| Field | Certification requirement |
|---|---|
| RID | Real scheme RID or domestic scheme RID |
| AID | Real application AID with selection rules |
| kernel type | Certified for interface and scheme |
| TAC/IAC | Complete 5-byte masks from scheme/acquirer/profile |
| limits | Complete values with currency/minor unit semantics |
| CAPKs | Complete modulus/exponent/checksum/expiry |
| contactless policy | Limits, TTQ/CTQ handling, CDCVM, outcome rules |
| source | document/version/owner |

**KRN-PROFILE-001 SHALL** reject placeholder strings such as `...`, dummy RIDs, dummy AIDs, and non-hex CAPK values in production or certification configuration.

**KRN-PROFILE-002 SHALL** validate all CAPK modulus/checksum strings as hex and expected length before loading.

---

# 17. API and ABI specification

## 17.1 Runtime initialization

```c
typedef struct {
    uint32_t abi_version;
    uint32_t struct_size;
    krn_callbacks_t callbacks;
    krn_allocator_t allocator;
    krn_timeouts_t timeouts;
    krn_log_policy_t log_policy;
    krn_security_policy_t security_policy;
} krn_runtime_t;

typedef struct krn_handle_s *krn_handle_t;

emv_status_t krn_init(const krn_config_blob_t *cfg,
                      const krn_runtime_t *runtime,
                      krn_handle_t *out_kernel);
```

**KRN-API-001 SHALL** validate `abi_version` and `struct_size` before dereferencing optional fields.

**KRN-API-002 SHALL** fail initialization if mandatory callbacks are absent.

## 17.2 Transaction parameters

```c
typedef struct {
    uint32_t struct_size;
    uint64_t amount_authorised_minor;
    uint64_t amount_other_minor;
    uint16_t currency_code;
    uint16_t terminal_country_code;
    uint8_t transaction_type;
    uint8_t terminal_type;
    uint8_t merchant_category_code[2];
    uint8_t interface_preference;
    const uint8_t *merchant_name_location;
    size_t merchant_name_location_len;
} krn_txn_params_t;

emv_status_t krn_set_transaction_params(krn_handle_t kernel,
                                        const krn_txn_params_t *params);
```

**KRN-API-003 SHALL** define every amount in minor units and SHALL bind currency exponent handling to terminal/acquirer configuration.

## 17.3 Callback contract

```c
typedef struct {
    int (*transmit_apdu)(const uint8_t *cmd,
                         size_t cmd_len,
                         uint8_t *resp,
                         size_t *resp_len,
                         int timeout_ms);

    krn_pin_result_t (*request_pin)(krn_pin_method_t method,
                                    const krn_pin_request_t *request);

    void (*display_message)(uint16_t message_id,
                            const char *fallback_text,
                            int severity,
                            int duration_ms);

    int (*send_online_request)(const uint8_t *icc_data,
                               size_t icc_data_len,
                               krn_online_response_t *response,
                               int timeout_ms);

    int (*get_unpredictable_number)(uint8_t *un,
                                    size_t len);

    void (*log_event)(const krn_log_event_t *event);

    void (*contactless_outcome)(const krn_contactless_outcome_t *outcome);
} krn_callbacks_t;
```

**KRN-API-004 SHALL** define buffer ownership for every callback. Unless otherwise stated, the caller owns input buffers and the callee owns no persistent reference after callback return.

**KRN-API-005 SHALL** be single-threaded and non-reentrant unless an explicit future ABI version defines concurrency semantics.

**KRN-API-006 SHALL** provide bounded callback timeouts for APDU transport, PIN entry, host authorization, and contactless UI handling.

## 17.4 Transaction execution

```c
typedef enum {
    KRN_OUTCOME_APPROVED_OFFLINE,
    KRN_OUTCOME_DECLINED_OFFLINE,
    KRN_OUTCOME_APPROVED_ONLINE,
    KRN_OUTCOME_DECLINED_ONLINE,
    KRN_OUTCOME_TRY_AGAIN,
    KRN_OUTCOME_ALTERNATE_INTERFACE,
    KRN_OUTCOME_SELECT_NEXT,
    KRN_OUTCOME_TERMINATED,
    KRN_OUTCOME_ERROR
} krn_outcome_t;

krn_outcome_t krn_run_transaction(krn_handle_t kernel);
```

**KRN-API-007 SHALL** return stable error codes retrievable after terminal outcome.

---

# 18. Security, logging, and privacy

## 18.1 Data classification

| Data | Classification | Logging policy |
|---|---|---|
| PAN | Cardholder data | Mask all but last 4 digits |
| Track 2 equivalent data | Sensitive cardholder data | Never log raw value |
| Clear PIN | Secret | Never visible to kernel |
| PIN block | Sensitive authentication data | Never log, never copy into general memory |
| CAPK | Public integrity-critical | May log key ID, RID, index, expiry, not full modulus in normal logs |
| ARQC/ARPC | Sensitive transaction cryptographic data | Debug only under certified support mode |
| TVR/TSI/CID | Transaction diagnostics | May log |
| APDU command/response | Mixed sensitivity | Mask according to tag-level policy |

**KRN-LOG-001 SHALL** enforce tag-aware masking before log emission.

**KRN-LOG-002 SHALL** disable full APDU logging in production unless certified support mode is enabled by policy.

**KRN-LOG-003 SHALL** exclude cardholder data, clear PIN, PIN block, and secret material from crash dumps.

**KRN-LOG-004 SHALL** make debug builds cryptographically and operationally distinguishable from production builds.

## 18.2 Randomness

**KRN-RNG-001 SHALL** obtain unpredictable numbers from an approved hardware RNG, secure OS RNG, or certified platform RNG callback.

**KRN-RNG-002 SHALL** reject all-zero, repeated where prohibited, or failed RNG outputs according to profile policy.

---

# 19. Error handling and recovery

## 19.1 Error taxonomy

| Error class | Examples | Handling |
|---|---|---|
| API misuse | invalid state, null handle, invalid params | Return API error, no card I/O |
| Configuration invalid | bad signature, bad schema, invalid CAPK | Reject configuration |
| Card protocol | malformed TLV, APDU status failure, timeout | State-specific transition |
| Card removal | contact removed, RF field lost | Contactless/contact policy outcome |
| ODA failure | missing CAPK, certificate failure, signature mismatch | Set TVR and proceed to TAA unless fatal |
| CVM failure | PED unavailable, PIN fail, CVM not performed | Set TVR and proceed according to CVM/TAA rules |
| Host failure | timeout, malformed response, unavailable | Apply unable-to-go-online/default policy |
| Script failure | script APDU fails | Set TVR Byte 5 script failure bit and continue/abort per profile |
| Internal fault | memory bounds, invariant failure | Terminate safely, no approval by default |

**KRN-ERR-001 SHALL** define every error code in a stable ABI table.

**KRN-ERR-002 SHALL** prefer fail-closed behavior where standards/profile do not explicitly permit continuation.

---

# 20. Performance and resource model

Performance limits shall be tiered by device class and must exclude Level 1 card response latency and host network roundtrip unless explicitly stated.

| Tier | Device class | Code/static target | Transaction context target | Kernel-only target |
|---|---|---:|---:|---:|
| A | Cortex-M / RTOS | <= 256 KB where feasible | <= 4 KB where feasible | Platform-profile-defined |
| B | Linux embedded POS | <= 1 MB where feasible | <= 32 KB where feasible | Platform-profile-defined |
| C | Android POS | No hard memory limit | No hard memory limit | UX/profile-defined |

**KRN-PERF-001 SHALL** measure ODA RSA/ECC operations separately from TLV parsing and APDU overhead.

**KRN-PERF-002 SHALL** define certification performance targets in the product profile, not in generic prose.

---

# 21. Testing and certification evidence

## 21.1 Test layers

| Layer | Required tests |
|---|---|
| Unit | TLV parser, DOL parser, APDU builder, TVR/TSI/CID bitmaps, CVM parser, TAA, config validator |
| Integration | Simulated card scripts for successful and adverse flows |
| Replay | Deterministic replay of masked APDU traces |
| Fuzz | TLV, APDU response parser, DOL parser, configuration parser |
| ODA crypto | Complete executable SDA, DDA, CDA vectors |
| Contact L2 pretest | Lab/tool-compatible contact test cases |
| Contactless/C-8 pretest | Lab/tool-compatible contactless/C-8 test cases |
| Security | static analysis, memory sanitizer, bounds checks, log masking checks |
| PCI/PED integration | PIN boundary, no clear PIN exposure, no unauthorized PIN block copying |

## 21.2 Certification evidence matrix

| Artifact | Required content | Format |
|---|---|---|
| Conformance statement | Requirement-to-standard-to-test mapping | Spreadsheet or database |
| Requirements traceability matrix | `KRN-*` to tests and evidence | Spreadsheet/CSV |
| Certified configuration manifest | Real AIDs, CAPKs, TAC/IAC, limits, profile source | Signed JSON/binary |
| Masked APDU traces | Every pretest and lab scenario | JSON/PCAP-like structured logs |
| ODA vector report | Complete cryptographic input/output and pass/fail | JSON plus report |
| Unit/integration report | Coverage, environment, compiler, target | HTML/XML |
| Static analysis report | MISRA C/CERT C or product-standard equivalent | Tool report |
| Fuzzing report | Corpus, iterations, crashes, coverage | Tool report |
| PCI PTS integration statement | PED boundary and PIN data-flow proof | Document |
| Lab submission archive | Device/kernel/config/test harness | Archive |

**KRN-CERT-001 SHALL** obtain EMV Level 2 approval for every claimed interface, kernel, and scheme profile.

**KRN-CERT-002 SHALL** not present illustrative profiles or placeholder vectors as certification evidence.

---

# 22. Deployment, updates, and rollback protection

**KRN-DPL-001 SHALL** support signed configuration updates for CAPK renewal, AID changes, TAC/IAC updates, limits, and profile changes.

**KRN-DPL-002 SHALL** implement anti-rollback through monotonic counters, secure storage, or signed override with auditable approval.

**KRN-DPL-003 SHALL** ensure atomic update: either the full new configuration is installed and verified or the previous verified configuration remains active.

**KRN-DPL-004 SHALL** retain versioned configuration identity in transaction logs.

---

# 23. Machine-readable annex requirements

## 23.1 State machine annex

The state machine annex shall be valid CSV or JSON. CSV fields containing commas must be quoted. Each row shall contain exactly:

```text
current_state,event,guard,next_state,action,error_code,test_ids
```

**KRN-ANNEX-001 SHALL** pass automated schema validation before release.

**KRN-ANNEX-002 SHALL** not contain semantic contradictions such as `next_state = SE` with an action saying “jump to TAA.”

## 23.2 TLV catalogue annex

The TLV catalogue shall include:

```text
tag,name,type,length_rule,presence_rule,source,interface,scheme,sensitivity,parser_rule,test_ids
```

**KRN-ANNEX-003 SHALL** classify DOLs as DOL values, not constructed TLV templates.

## 23.3 Scheme profile annex

The scheme profile annex shall be divided into:

| File | Use |
|---|---|
| `scheme_profiles.example.json` | Non-normative examples only, not loadable in production |
| `scheme_profiles.cert.json` | Real signed certification configuration |

**KRN-ANNEX-004 SHALL** reject placeholder values, ellipses, non-hex material, dummy AIDs, dummy RIDs, and dummy CAPKs from any production or certification profile.

## 23.4 ODA vector annex

**KRN-ANNEX-005 SHALL** contain complete cryptographic vectors. Scenario summaries are not test vectors.

---

# 24. Appendix A: Corrected APDU summary

| Command | CLA | INS | P1 | P2 | Data | Le/response note |
|---|---|---|---|---|---|---|
| SELECT Contact PSE | `00` | `A4` | `04` | `00` | `1PAY.SYS.DDF01` | FCI |
| SELECT Contactless PPSE | `00` | `A4` | `04` | `00` | `2PAY.SYS.DDF01` | FCI |
| SELECT AID | `00` | `A4` | `04` | profile-defined | AID | FCI |
| GPO | `80` | `A8` | `00` | `00` | `83 || L || PDOL values` | `80` or `77` response |
| READ RECORD | `00` | `B2` | record | `(SFI << 3) | 0x04` | none | Record TLV |
| INTERNAL AUTHENTICATE | `00` | `88` | `00` | `00` | DDOL values | Signed dynamic data, e.g. `9F4B` |
| VERIFY plaintext offline PIN | `00` | `20` | `00` | EMV plaintext PIN reference, commonly `80` | PED-produced PIN block | `9000` or `63Cx` |
| VERIFY enciphered offline PIN | `00` | `20` | `00` | EMV enciphered PIN reference, commonly `88` | PED/secure module-produced enciphered PIN block | `9000` or `63Cx` |
| GENERATE AC 1 | `80` | `AE` | request bits `00/40/80` plus profile flags | `00` | CDOL1 values | CID/AC/ATC/IAD |
| GENERATE AC 2 | `80` | `AE` | request bits/profile-defined | `00` | CDOL2 values | final CID/AC |
| EXTERNAL AUTHENTICATE | `00` | `82` | `00` | `00` | issuer authentication data | `9000` or failure |

---

# 25. Appendix B: Corrected status-word policy skeleton

The final implementation shall maintain a per-command and per-state SW1/SW2 table. The following skeleton is mandatory minimum behavior.

| Command | SW | Handling |
|---|---|---|
| SELECT | `9000` | Parse FCI |
| SELECT | `6A82` | Candidate not found, try next candidate or no common AID |
| SELECT | `6283` | Handle invalidated application per profile |
| GPO | `9000` | Parse response template |
| GPO | `6985` | Conditions not satisfied, fail or try next according to profile |
| READ RECORD | `9000` | Parse record |
| READ RECORD | `6A83` | Record not found, handle according to AFL/profile |
| VERIFY | `9000` | PIN successful |
| VERIFY | `63Cx` | PIN failed with tries remaining |
| GENERATE AC | `9000` | Parse CID and cryptogram response |
| EXTERNAL AUTHENTICATE | `9000` | Issuer authentication successful |
| EXTERNAL AUTHENTICATE | other failure | Set issuer authentication failed TVR bit if attempted |

---

# 26. Appendix C: Non-normative example profile warning

The following values are illustrative only and shall not be used in production or certification:

```json
{
  "profile_class": "EXAMPLE_ONLY",
  "loadable_in_production": false,
  "aid": "A0000000000000",
  "rid": "A000000000",
  "capk": {
    "modulus_hex": "EXAMPLE_NOT_A_REAL_KEY",
    "exponent_hex": "010001"
  }
}
```

Any file containing `...`, invalid hex characters, dummy RIDs, dummy AIDs, or fictitious CAPKs shall fail production validation.

---

# 27. Appendix D: Release checklist

Before freezing this specification as certification baseline, complete the checklist below.

| Item | Required evidence | Status |
|---|---|---|
| Licensed EMV Book 3 bitmaps verified | Bitmap mapping review record | Pending |
| C-8 outcome model verified | C-8 profile review record | Pending |
| Scheme profiles real and signed | `scheme_profiles.cert.json` | Pending |
| CAPKs real and current | CAPK manifest with source/version | Pending |
| ODA vectors executable | Complete cryptographic vector file | Pending |
| State machine annex valid | Schema validation report | Pending |
| TLV catalogue valid | Schema validation report | Pending |
| APDU/SW table complete | State-specific APDU table | Pending |
| Requirement/test traceability complete | RTM file | Pending |
| PED integration reviewed | PCI PTS boundary document | Pending |
| Lab pretest passed | Tool/lab report | Pending |

---

# End of Hyperion-KRN EMV Level 2 Kernel Specification v3.1
