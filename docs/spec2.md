# EMV Level 2 Kernel Specification – Hyperion Kernel (Hyperion‑KRN) – v3.0

**Version:** 3.0  
**Status:** Implementation and certification baseline  
**Target EMV Baseline:** EMV Contact Chip Specifications v4.4 (with v4.3 as legacy compatibility floor)  
**Contactless Baseline:** EMV Contactless Kernel Specification Book C‑8 v1.0  
**PCI Baseline:** PCI PTS POI v7.0  
**Document Control:** This specification is normative for all engineering, testing, and certification activities related to the Hyperion EMV kernel.

---

## 1. Scope and Normative References

### 1.1. Scope
This document defines the **behaviour, interfaces, configuration, testing, and certification requirements** of the Hyperion EMV Level 2 kernel. The kernel executes EMV transaction logic for contact (ISO7816) and contactless (ISO14443) payment cards, but **does not** implement:
- Physical or electrical card interface (Level 1)
- PIN capture or secure PIN entry device (PED) logic
- Host (acquirer, issuer) authorisation messaging
- Issuer master key custody or cryptogram validation (except CAPKs for offline data authentication)

### 1.2. Normative References

| ID | Reference | Version | Applicability |
|----|-----------|---------|----------------|
| [EMV4.4] | EMV Contact Chip Specifications – Books 1‑4 | v4.4 | Core contact logic |
| [EMV4.3] | EMV Contact Chip Specifications – Books 1‑4 | v4.3 | Legacy compatibility floor |
| [C8] | EMV Contactless Kernel Specification Book C‑8 | v1.0 | Contactless unified kernel |
| [EMVCo L2] | EMV Level 2 Approval Process | current | Certification process |
| [PCI PTS] | PCI PIN Transaction Security POI Modular Requirements | v7.0 | PIN handling alignment |
| [ISO7816‑3] | Identification cards – Integrated circuit cards – Part 3 | latest | T=0/T=1 protocol |
| [ISO7816‑4] | Interindustry commands for interchange | latest | APDU structure |
| [ISO14443‑4] | Contactless – Part 4: Transmission protocol | latest | Contactless APDU |
| [ISO9564‑1] | PIN block formats | latest | Online PIN encryption |

**KRN‑REF‑001 SHALL** The implementation comply with all normative references. In case of conflict between references and this specification, the referenced standards prevail.

---

## 2. Trust Boundary and Responsibility Model

The kernel is one component inside a payment acceptance system. The following table defines ownership boundaries.

| Component | Responsibilities | Owned by | Security classification |
|-----------|------------------|----------|--------------------------|
| **EMV L2 kernel** | CAPK integrity checks; ODA (SDA, DDA, CDA); APDU orchestration; TVR/TSI setting; CDOL/DDOL construction; cryptogram response parsing; final decision (offline approve/decline/go online). | Hyperion kernel | Integrity‑critical, no confidentiality for CAPKs |
| **Secure PIN subsystem (PED)** | PIN capture, PIN block formatting (ISO9564‑1), online PIN encryption (DUKPT), offline PIN APDU handling. PCI PTS certified. | Terminal manufacturer / kernel integrator | Confidentiality‑critical |
| **Level 3 application** | UI, host communication, scripting environment, receipt printing. | Terminal application developer | Functional |
| **Acquirer / switch** | ISO 8583/ISO 20022 routing, authorisation request forwarding. | Acquirer | Functional |
| **Issuer / issuer processor** | Issuer master keys, ARQC validation, ARPC generation, issuer scripts. | Issuer | Confidentiality‑critical |

**KRN‑SEC‑001 SHALL** No issuer master key be stored or accessible inside the kernel.  
**KRN‑SEC‑002 SHALL** The kernel not generate ARQC, TC, or AAC; these cryptograms are returned by the card in response to GENERATE AC.  
**KRN‑SEC‑003 SHALL** The kernel treat CAPKs as **public keys**; they require integrity protection and authenticity, but not confidentiality. They may be stored in plaintext with a digital signature covering the configuration blob.  
**KRN‑SEC‑004 SHALL** PIN processing be delegated to a PCI PTS‑approved PED module; the kernel only receives a handle to a encrypted PIN block (for online) or a success/failure status (for offline). The kernel never accesses the clear PIN.

---

## 3. Supported Interfaces and Kernel Selection

The kernel supports three interface classes, each with distinct configuration and state machine behavior.

| Interface | Protocol | EMV Baseline | Preferred Kernel |
|-----------|----------|--------------|------------------|
| **Contact** | ISO7816‑3 (T=0 or T=1) | EMV4.4 | Scheme‑specific or C‑8 (if certified) |
| **Contactless** | ISO14443‑4 (contactless APDU) | EMV Contactless + C‑8 | C‑8 unified (preferred) |
| **Dual** | Auto‑detection | Both | Runtime selection based on card presence |

**KRN‑INT‑001 SHALL** The kernel be initialised with a configuration that lists allowed interfaces and the kernel type to use for each (e.g., `legacy_visa`, `legacy_mastercard`, `c8`).  
**KRN‑INT‑002 SHOULD** The C‑8 unified kernel be used for all contactless transactions to reduce certification maintenance.

---

## 4. Transaction State Machine

The kernel implements a deterministic finite state machine with the states defined below. Transitions are triggered by events (APDU responses, timeouts, callback results) and guarded by transaction context.

### 4.1. State List

| State ID | Name | Description |
|----------|------|-------------|
| `S0` | **Idle** | Kernel initialised, no transaction in progress. |
| `S1` | **Initialised** | Transaction parameters loaded (amount, currency, terminal config). |
| `S2` | **AppSelection** | Card detected; performing PSE/PPSE and AID selection. |
| `S3` | **GPO** | GET PROCESSING OPTIONS sent; AIP/AFL received. |
| `S4` | **ReadRecords** | Reading application data via AFL. |
| `S5` | **ODA** | Offline Data Authentication (SDA/DDA/CDA) performed. |
| `S6` | **ProcessingRestrictions** | Checking dates, currency, application usage. |
| `S7` | **CVM** | Cardholder verification (PIN, signature, CDCVM, etc.). |
| `S8` | **TerminalRiskMgmt** | Floor limit, random selection, velocity checks. |
| `S9` | **TAA** | Terminal Action Analysis (evaluating TACs and IACs). |
| `S10` | **GenerateAC1** | First GENERATE AC sent; cryptogram (ARQC/TC/AAC) received. |
| `S11` | **Online** | (if ARQC) Waiting for host authorisation response. |
| `S12** | **GenerateAC2** | Second GENERATE AC with host response (ARPC) sent; final cryptogram received. |
| `S13** | **IssuerScript** | Executing issuer scripts (if any). |
| `S14** | **Complete** | Final outcome determined, kernel reset. |
| `SE` | **Error** | Unrecoverable error (card removed, protocol violation, etc.). |

### 4.2. Transition Table (Excerpt – Full table in Appendix E)

| Current State | Event | Guard | Next State | Action |
|---------------|-------|-------|------------|--------|
| `S0` | `krn_set_transaction_params()` | – | `S1` | Store amount, currency, terminal config. |
| `S1` | `card_detected()` callback | – | `S2` | Start PSE/PPSE selection. |
| `S2` | `SELECT` returns `90 00` with FCI | AID selected | `S3` | Build PDOL, send GPO. |
| `S2` | `SELECT` fails or no common AID | – | `SE` | Set error `KRN_ERR_NO_COMMON_AID`. |
| … | … | … | … | … |
| `S10` | `GENERATE AC` returns `90 00` with cryptogram | CID indicates ARQC | `S11` | Build host request data. |
| `S10` | `GENERATE AC` returns cryptogram | CID indicates TC | `S14` | Offline approval. |
| `S10` | `GENERATE AC` returns cryptogram | CID indicates AAC | `S14` | Offline decline. |

**KRN‑FSM‑001 SHALL** The kernel implement state transitions as defined in the full transition table (Appendix E).  
**KRN‑FSM‑002 SHALL** Any unexpected APDU response (SW1/SW2 not `90 00` or `63 CX`) or callback error transition to `SE` and set an error code.

---

## 5. EMV Data Object Dictionary

The kernel must parse, compose, and validate the following tags. All tags follow BER‑TLV as per EMV Book 3. The table includes required presence and handling.

### 5.1. Common tags (contact and contactless)

| Tag | Name | Format | Presence | Notes |
|-----|------|--------|----------|-------|
| `4F` | AID | Primitive, variable | Mandatory | Used in SELECT |
| `50` | Application Label | Primitive, variable | Recommended | For UI |
| `57` | Track 2 Equivalent Data | Primitive, variable | Mandatory | For host authorisation |
| `5A` | PAN | Primitive, variable | Mandatory | Masked in logs |
| `5F20` | Cardholder Name | Primitive, variable | Optional | – |
| `5F24` | Application Expiration Date | Primitive, 3 bytes | Mandatory | YYMMDD |
| `5F25` | Application Effective Date | Primitive, 3 bytes | Optional | YYMMDD |
| `5F28` | Issuer Country Code | Primitive, 2 bytes | Mandatory | Numeric |
| `5F2A` | Transaction Currency Code | Primitive, 2 bytes | Mandatory (terminal) | Numeric |
| `5F34` | Application PAN Sequence Number | Primitive, 1 byte | Optional | – |
| `82` | AIP | Primitive, 2 bytes | Mandatory after GPO | Bits for card capabilities |
| `84` | DF Name (PPSE) | Primitive, variable | For contactless | – |
| `8C` | CDOL1 | Constructed? | If present | Sequence of tag‑length pairs; kernel interprets as DOL |
| `8D` | CDOL2 | Constructed? | If present | Sequence of tag‑length pairs |
| `8E` | CVM List | Constructed | Mandatory | List of CVM rules |
| `91` | Issuer Authentication Data | Primitive, variable | For ARPC | – |
| `94` | AFL | Primitive, variable | Mandatory after GPO | List of record ranges |
| `95` | TVR | Primitive, 5 bytes | Kernel sets | Bit‑field; see section 5.3 |
| `9A` | Transaction Date | Primitive, 3 bytes | Terminal sets | YYMMDD |
| `9B` | TSI | Primitive, 2 bytes | Kernel sets | Transaction status indicator |
| `9C` | Transaction Type | Primitive, 1 byte | Terminal sets | – |
| `9F02` | Amount, Authorised | Primitive, 6 bytes | Terminal sets | – |
| `9F03` | Amount, Other | Primitive, 6 bytes | For cashback | – |
| `9F07` | Application Usage Control | Primitive, 2 bytes | From card | Restriction checks |
| `9F09` | Application Version Number | Primitive, 2 bytes | Mandatory | Version comparison |
| `9F10` | Issuer Application Data | Primitive, variable | Host data | – |
| `9F1A` | Terminal Country Code | Primitive, 2 bytes | Terminal sets | – |
| `9F1E` | Interface Device Serial Number | Primitive, variable | Optional | – |
| `9F26` | Application Cryptogram | Primitive, 8 bytes | From card | – |
| `9F27` | Cryptogram Information Data | Primitive, 1 byte | From card | See section 5.2 |
| `9F33` | Terminal Capabilities | Primitive, 3 bytes | Terminal sets | – |
| `9F34` | CVM Results | Primitive, 3 bytes | Kernel sets | – |
| `9F35` | Terminal Type | Primitive, 1 byte | Terminal sets | – |
| `9F36` | ATC | Primitive, 2 bytes | From card | – |
| `9F37` | Unpredictable Number | Primitive, 4 bytes | Terminal generates | – |
| `9F4C` | ICC Dynamic Number | Primitive, variable | For CDA | – |
| `9F4E` | Merchant Category Code | Primitive, 2 bytes | Terminal sets | – |
| `9F6C` | CTQ | Primitive, 1 byte | For contactless | – |
| `9F6E` | Form Factor Indicator | Primitive, 1 byte | For mobile | – |
| `9F66` | TTQ | Primitive, 4 bytes | For contactless | – |
| `9F7C` | Customer Exclusive Data | Primitive, variable | Optional | – |

**KRN‑TLV‑001 SHALL** The kernel reject any transaction if a mandatory tag is missing or malformed, set the appropriate TVR bits, and proceed to Terminal Action Analysis (TAA).  
**KRN‑TLV‑002 SHALL** The kernel support DOLs (CDOL, DDOL, PDOL, TDOL) by parsing the tag‑length pairs and constructing data fields in the order defined.

### 5.2. Cryptogram Information Data (CID) – Bit‑Level Specification

The CID byte (`9F27`) encodes the cryptogram type in the high‑order bits. The kernel shall decode as follows:

```c
typedef enum {
    KRN_CRYPTOGRAM_AAC = 0,   // Application Authentication Cryptogram (decline)
    KRN_CRYPTOGRAM_TC  = 1,   // Transaction Certificate (offline approve)
    KRN_CRYPTOGRAM_ARQC = 2,  // Authorization Request Cryptogram (go online)
    KRN_CRYPTOGRAM_AAR  = 3,  // Application Authorisation Referral (rare)
    KRN_CRYPTOGRAM_RESERVED = 4
} krn_cryptogram_type_t;

krn_cryptogram_type_t krn_decode_cid(uint8_t cid) {
    uint8_t type_bits = (cid >> 6) & 0x03; // bits 7 and 6
    switch (type_bits) {
        case 0: return KRN_CRYPTOGRAM_AAC;
        case 1: return KRN_CRYPTOGRAM_TC;
        case 2: return KRN_CRYPTOGRAM_ARQC;
        case 3: return KRN_CRYPTOGRAM_AAR;
        default: return KRN_CRYPTOGRAM_RESERVED;
    }
}
```

**KRN‑CID‑001 SHALL** The kernel interpret CID bits 7 and 6 as per the table above. Any other bits (0‑5) shall be ignored for cryptogram type determination but preserved for logging.

### 5.3. TVR Bits – Normative Byte and Bit Definitions

TVR is 5 bytes, indexed 0 to 4 (byte 0 = first byte). The following bits are mandatory for kernel to set.

| Byte | Bit (7‑0) | EMV Condition | Set by | Symbolic Constant (example) |
|------|-----------|---------------|--------|----------------------------|
| 0 | 7 | Offline data authentication was not performed | ODA engine | `TVR_B0_OFFLINE_DATA_AUTH_NOT_PERFORMED` |
| 0 | 6 | SDA failed | ODA engine | `TVR_B0_SDA_FAILED` |
| 0 | 5 | ICC data missing | TLV validator | `TVR_B0_ICC_DATA_MISSING` |
| 0 | 4 | Card is on the exception file | Terminal risk mgmt | `TVR_B0_CARD_ON_EXCEPTION_FILE` |
| 0 | 3 | DDA failed | ODA engine | `TVR_B0_DDA_FAILED` |
| 0 | 2 | CDA failed | ODA engine | `TVR_B0_CDA_FAILED` |
| 1 | 7 | Cardholder verification failed | CVM module | `TVR_B1_CVM_FAILED` |
| 1 | 6 | Unrecognised CVM | CVM module | `TVR_B1_UNRECOGNISED_CVM` |
| 1 | 5 | PIN try limit exceeded | CVM module (from VERIFY response) | `TVR_B1_PIN_TRY_LIMIT_EXCEEDED` |
| 1 | 4 | PIN entry required and PIN pad not present | CVM module | `TVR_B1_PIN_PAD_NOT_PRESENT` |
| 1 | 3 | PIN entry required but PIN pad not working | CVM module | `TVR_B1_PIN_PAD_INOPERATIVE` |
| 2 | 7 | Transaction exceeds floor limit | TRM | `TVR_B2_EXCEEDS_FLOOR_LIMIT` |
| 2 | 6 | Lower consecutive offline limit exceeded | TRM | `TVR_B2_LOWER_CONSECUTIVE_OFFLINE_LIMIT` |
| 2 | 5 | Upper consecutive offline limit exceeded | TRM | `TVR_B2_UPPER_CONSECUTIVE_OFFLINE_LIMIT` |
| 2 | 4 | Random selection triggered | TRM | `TVR_B2_RANDOM_SELECTION_TRIGGERED` |
| 2 | 3 | Transaction selected for random force online | TRM | `TVR_B2_RANDOM_FORCE_ONLINE` |
| 3 | 7 | Expired card | Processing restrictions | `TVR_B3_EXPIRED_CARD` |
| 3 | 6 | Card not yet effective | Processing restrictions | `TVR_B3_CARD_NOT_EFFECTIVE` |
| 3 | 5 | Service not allowed | Processing restrictions | `TVR_B3_SERVICE_NOT_ALLOWED` |
| 3 | 4 | Application not yet effective | Processing restrictions | `TVR_B3_APP_NOT_EFFECTIVE` |
| 3 | 3 | Application expired | Processing restrictions | `TVR_B3_APP_EXPIRED` |
| 4 | 7 | New card | Card data | `TVR_B4_NEW_CARD` |
| 4 | 6 | Cardholder activated | Card data | `TVR_B4_CARDHOLDER_ACTIVATED` |

**KRN‑TVR‑001 SHALL** The kernel use the symbolic constants above when setting TVR bits; the raw hex values shall not be used directly in code without a mapping layer.  
**KRN‑TVR‑002 SHALL** The kernel clear TVR before each transaction.

### 5.4. TSI (Transaction Status Indicator) – Byte and Bit Definitions

TSI is 2 bytes, defined as follows:

| Byte | Bit | Condition | Set by |
|------|-----|-----------|--------|
| 0 | 7 | Offline data authentication performed | ODA engine |
| 0 | 6 | Cardholder verification performed | CVM module |
| 0 | 5 | Card risk management performed | Card (from AIP) |
| 0 | 4 | Issuer authentication performed | Kernel after online response |
| 0 | 3 | Terminal risk management performed | TRM engine |
| 0 | 2 | Script processing performed | Script processor |
| 0 | 1 | … (reserved) | – |

**KRN‑TSI‑001 SHALL** The kernel set TSI bits accordingly after each phase.

---

## 6. APDU Command Specification

The kernel must construct, send, and parse the following APDUs. All APDUs conform to ISO7816‑4.

### 6.1. SELECT (by DF name or PSE/PPSE)

| Command | CLA | INS | P1 | P2 | Lc | Data | Le |
|---------|-----|-----|----|----|----|------|----|
| SELECT by DF name | `00` | `A4` | `04` | `00` | len | AID or DF name | `00` |
| SELECT PSE (contact) | `00` | `A4` | `04` | `00` | `0E` | `2PAY.SYS.DDF01` (padded) | `00` |
| SELECT PPSE (contactless) | `00` | `A4` | `04` | `00` | `0E` | `2PAY.SYS.DDF01` (padded) | `00` |

**Response:** FCI template (`6F`) containing `84` (DF name) and `A5` (proprietary). For PPSE, `A5` contains `BF0C` with a list of `4F` (AID) entries.

### 6.2. GET PROCESSING OPTIONS (GPO)

| Command | CLA | INS | P1 | P2 | Lc | Data (PDOL) | Le |
|---------|-----|-----|----|----|----|-------------|----|
| GPO | `80` | `A8` | `00` | `00` | len | PDOL values | `00` |

**Response:** `77` template with `82` (AIP) and `94` (AFL) or `80` (if no AFL).

### 6.3. READ RECORD

| Command | CLA | INS | P1 | P2 | Le |
|---------|-----|-----|----|----|----|
| READ RECORD | `00` | `B2` | record number | (SFI << 3) \| 0x04 (or 0x00) | `00` |

**Notes:**
- P2 = (SFI << 3) | 0x04 for read record(s) with P1 = record number.
- For the first record of an SFI, P1 = 1, P2 = (SFI << 3) | 0x04.
- Response: the record as BER‑TLV.

**KRN‑APDU‑001 SHALL** The kernel construct READ RECORD APDU with correct SFI encoding.

### 6.4. INTERNAL AUTHENTICATE (for DDA)

| Command | CLA | INS | P1 | P2 | Lc | Data (DDOL) | Le |
|---------|-----|-----|----|----|----|-------------|----|
| INTERNAL AUTH | `00` | `88` | `00` | `00` | len | DDOL values | `00` |

**Response:** Signed dynamic data (DDA signature) as a primitive TLV (tag `9F4C` for ICC Dynamic Number, plus signature).

**KRN‑APDU‑002 SHALL** The kernel only use INTERNAL AUTHENTICATE for DDA, not for SDA.

### 6.5. VERIFY (offline PIN)

| Command | CLA | INS | P1 | P2 | Lc | Data | Le |
|---------|-----|-----|----|----|----|------|----|
| VERIFY (offline) | `00` | `20` | `00` | `00` | len | PIN block (encrypted by PED) | – |

**Response:** `90 00` (success) or `63 CX` (try limit exceeded, where X = remaining tries).

**KRN‑APDU‑003 SHALL** The kernel delegate PIN block construction to the PED via callback; it never constructs a PIN block.  
**KRN‑APDU‑004 SHALL** The kernel interpret `63 CX` and set TVR bit `PIN_TRY_LIMIT_EXCEEDED` if X == 0.

### 6.6. GENERATE AC (First and Second)

| Command | CLA | INS | P1 | P2 | Lc | Data | Le |
|---------|-----|-----|----|----|----|------|----|
| GENERATE AC (first) | `80` | `AE` | cryptogram type request | `00` | len | CDOL1 values | `00` |
| GENERATE AC (second) | `80` | `AE` | `00` (or cryptogram type) | `00` | len | CDOL2 values (including ARPC) | `00` |

**Encoding of P1 (first GENERATE AC):**

| Bits | Meaning |
|------|---------|
| Bit 8 (0x80) | Always 1 for first GENERATE AC (as per EMV) |
| Bits 7‑1 | Encodes the requested cryptogram type: `0` for AAC, `1` for TC, `2` for ARQC (as per scheme). |

**Implementation:**
```c
uint8_t p1 = 0x80; // first GENERATE AC flag
if (request == ARQC) p1 |= 0x02;
else if (request == TC) p1 |= 0x01;
else if (request == AAC) p1 |= 0x00;
```

**KRN‑APDU‑005 SHALL** The kernel construct CDOL1/CDOL2 data by fetching the required tags from terminal context and concatenating values in tag order.  
**KRN‑APDU‑006 SHALL** The kernel not generate the cryptogram; it only parses the card’s response.  
**KRN‑APDU‑007 SHALL** The kernel parse the response and extract CID, AC, ATC, IAD.

### 6.7. EXTERNAL AUTHENTICATE (if required)

| Command | CLA | INS | P1 | P2 | Lc | Data (ARPC) | Le |
|---------|-----|-----|----|----|----|-------------|----|
| EXTERNAL AUTH | `00` | `82` | `00` | `00` | len | ARPC from host | – |

**Response:** `90 00` on success.

**KRN‑APDU‑008 SHALL** The kernel support EXTERNAL AUTHENTICATE if required by the card’s AIP bit.

---

## 7. Offline Data Authentication (ODA)

The kernel implements SDA, DDA, and CDA as per EMV Book 3, with the following mandatory steps.

### 7.1. CAPK Management

- CAPKs are stored per RID + key index as part of kernel configuration.
- Each CAPK record contains: RID (5 bytes), key index (1 byte), modulus (n), exponent (e), expiration date, and a digital signature over the configuration (covering all CAPKs and other parameters) for integrity.
- **KRN‑ODA‑001 SHALL** Before using a CAPK, the kernel verify its integrity by checking the configuration signature (using a root of trust key). Expiration date shall be checked against current date.
- **KRN‑ODA‑002 SHALL** CAPKs be treated as **public keys**; confidentiality is not required, but integrity and authenticity are mandatory.

### 7.2. Certificate Recovery

For SDA and DDA, the kernel performs:

1. Recover the issuer public key certificate:
   - Use CAPK to verify the digital signature of the issuer public key certificate.
   - Extract the issuer public key (modulus, exponent).
2. Recover the ICC public key certificate (for DDA) using the issuer public key.
3. For SDA: verify the static application data signature using the recovered issuer public key.
4. For DDA: perform INTERNAL AUTHENTICATE, verify the dynamic signature using the recovered ICC public key.

**KRN‑ODA‑003 SHALL** If any certificate recovery or signature verification fails, set TVR bits accordingly (e.g., `TVR_B0_SDA_FAILED` or `TVR_B0_DDA_FAILED`) and proceed to TAA.  
**KRN‑ODA‑004 SHALL** For CDA, the dynamic data signed during GENERATE AC (first) shall include the cryptogram. Verification is performed after the first GENERATE AC, using the same ICC public key.

---

## 8. Processing Restrictions

**KRN‑REST‑001 SHALL** The kernel perform the following checks in order:

| Check | Condition | TVR bit | Action on failure |
|-------|-----------|---------|-------------------|
| Application version | Card version not in terminal list | `TVR_B3_APP_VERSION_MISMATCH` (bit 1 of byte 3) | Set TVR, continue |
| Effective/expiry dates | Current date outside [effective, expiry] | `TVR_B3_APP_NOT_EFFECTIVE` or `TVR_B3_APP_EXPIRED` | Set TVR, continue |
| Currency | Card currency code != terminal currency code | `TVR_B4_CURRENCY_MISMATCH` (bit 7 of byte 4) | Set TVR, continue |
| Application Usage Control | AUC bits disallow transaction type (e.g., cash, domestic) | `TVR_B3_SERVICE_NOT_ALLOWED` | Set TVR, continue |

**KRN‑REST‑002 SHALL** If any restriction fails, the kernel **does not** automatically decline; it sets TVR bits and proceeds to Terminal Action Analysis.

---

## 9. Cardholder Verification (CVM)

The kernel evaluates the CVM list as per EMV Book 3, with priority order given by the card. The following CVM methods are supported:

| Method Code | Method | Handling |
|-------------|--------|----------|
| `01` | Offline plaintext PIN | Call `request_pin(offline, ...)`; send VERIFY APDU via kernel (but PIN block from PED). |
| `02` | Online PIN | Call `request_pin(online, ...)`; receive handle to encrypted PIN block; pass to host in online request. |
| `03` | Signature | (If permitted) call `notify_signature_required()`; set TVR bit `CVM_FAILED` if not performed. |
| `04` | No CVM | Accept if amount ≤ CVM limit. |
| `05` | CDCVM | Check consumer device CVM flag (from card or terminal); if true, treat as successful CVM. |

**KRN‑CVM‑001 SHALL** The kernel enforce CVM limits per scheme: if transaction amount exceeds the limit for a method, that method is considered failed.  
**KRN‑CVM‑002 SHALL** After CVM evaluation, set TVR byte 1 bits accordingly (`CVM_FAILED`, `UNRECOGNISED_CVM`, `PIN_TRY_LIMIT_EXCEEDED`, etc.).  
**KRN‑CVM‑003 SHALL** The kernel not access the clear PIN; for offline PIN, the PED returns only success/failure and try counter.

---

## 10. Terminal Risk Management (TRM)

**KRN‑TRM‑001 SHALL** The kernel support configurable:

- **Floor limit** (amount below which offline approval is allowed)
- **Random selection percentage** (target RS %) – a deterministic algorithm using ATC and unpredictable number to select a transaction for online forcing.
- **Velocity limits** (optional) – number of consecutive offline transactions before forcing online.

**Random selection algorithm (EMV Book 3):**

Let `rand = (ATC + UN) & 0xFFFF`.  
If `rand < (Target_RS% * 65536 / 100)`, then force online.

**KRN‑TRM‑002 SHALL** If floor limit is exceeded or random selection triggers, set TVR bit `EXCEEDS_FLOOR_LIMIT` or `RANDOM_SELECTION_TRIGGERED`.  
**KRN‑TRM‑003 MAY** Implement velocity limits using a non‑volatile counter.

---

## 11. Terminal Action Analysis (TAA)

The kernel combines Terminal Action Codes (TAC) and Issuer Action Codes (IAC) to determine the next action. Both TAC and IAC are 5‑byte masks applied to TVR.

**KRN‑TAA‑001 SHALL** The kernel perform the following evaluation in order:

```c
// First, check for denial conditions
if ( (tvr & (tac_denial | iac_denial)) != 0 ) {
    request_cryptogram = AAC;
} 
// Else, if terminal is online capable and online conditions true
else if ( terminal_online_capable && 
          (tvr & (tac_online | iac_online)) != 0 ) {
    request_cryptogram = ARQC;
}
// Else, if terminal is NOT online capable and default denial conditions true
else if ( !terminal_online_capable && 
          (tvr & (tac_default | iac_default)) != 0 ) {
    request_cryptogram = AAC;  // or TC if scheme allows offline approval
}
// Else, default action (typically go online or offline approve)
else {
    request_cryptogram = default_cryptogram; // from configuration
}
```

**KRN‑TAA‑002 SHALL** The kernel use the final request cryptogram type (AAC, TC, or ARQC) in the first GENERATE AC command.  
**KRN‑TAA‑003 SHALL** The IAC values be part of the kernel configuration (per scheme and per AID).

---

## 12. Generate AC and Cryptogram Handling

### 12.1. First Generate AC

**KRN‑GAC‑001 SHALL** The kernel construct CDOL1 data by iterating through the card’s CDOL1 tag list, fetching each tag from the terminal context (e.g., `9F02`, `9A`, etc.).  
**KRN‑GAC‑002 SHALL** The kernel set P1 according to the requested cryptogram type (section 6.6).  
**KRN‑GAC‑003 SHALL** The kernel send GENERATE AC and parse the response, extracting CID, AC, ATC, and IAD.

### 12.2. Online Authorisation Interface

**KRN‑GAC‑004 SHALL** If the card returns ARQC, the kernel:

- Assemble the online authorisation request data: TLV list containing at least `82` (AIP), `95` (TVR), `9F26` (ARQC), `9F36` (ATC), `5A` (PAN), `57` (Track 2), `9F10` (IAD), `9F37` (UN), etc.
- Pass the data to the Level 3 application via callback `send_online_auth_request()`.
- Wait for host response (ARPC, issuer scripts, approval/decline indication, timeout).

**KRN‑GAC‑005 SHALL** If host response contains an ARPC, the kernel include it in CDOL2 for the second GENERATE AC.

### 12.3. Second Generate AC

**KRN‑GAC‑006 SHALL** The kernel construct CDOL2 data (including ARPC if present) and send GENERATE AC with P1= `0x00` (second).  
**KRN‑GAC‑007 SHALL** The kernel parse the final cryptogram: TC (approve), AAC (decline). This final decision overrides any previous offline decision.

---

## 13. Issuer Script Processing

**KRN‑SCR‑001 SHALL** The kernel receive issuer scripts from the host as a list of APDU commands.  
**KRN‑SCR‑002 SHALL** The kernel execute each script APDU in order, capturing the response SW1/SW2.  
**KRN‑SCR‑003 SHALL** The kernel report script execution results (success/failure, SW1/SW2) back to the host via the online response interface.  
**KRN‑SCR‑004 SHALL** If a script fails (SW1/SW2 not `90 00`), the kernel continue processing remaining scripts unless the scheme mandates abortion (configured per scheme).

---

## 14. Configuration Model

The kernel is initialised with a **signed configuration package** in JSON format, bundled as a binary blob with a digital signature.

### 14.1. Configuration Schema (excerpt)

```json
{
  "version": "1.0",
  "signature": "base64-encoded-signature",
  "kernel_defaults": {
    "terminal_country_code": 826,
    "terminal_currency_code": 826,
    "terminal_capabilities": "E0F8C8",
    "terminal_type": 0x22
  },
  "schemes": [
    {
      "rid": "A000000003",
      "name": "Visa",
      "aids": [
        {
          "aid": "A0000000031010",
          "priority": 10,
          "partial_selection": true,
          "interfaces": ["contact", "contactless"],
          "kernel_type": "c8",
          "tac_online": "0000000000",
          "tac_denial": "0000000000",
          "tac_default": "8000000000",
          "iac_online": "0000000000",
          "iac_denial": "0000000000",
          "iac_default": "0000000000",
          "floor_limit": 0,
          "cvm_limit_contact": 5000,
          "random_selection_percent": 5,
          "contactless_transaction_limit": 5000,
          "contactless_cvm_limit": 3000
        }
      ],
      "capks": [
        {
          "key_index": 1,
          "modulus": "hex-string",
          "exponent": "010001",
          "expiry": "2028-12-31",
          "checksum": "hash"
        }
      ]
    }
  ]
}
```

**KRN‑CFG‑001 SHALL** The kernel reject any configuration with an invalid signature, expired expiry, version mismatch, or missing mandatory fields.  
**KRN‑CFG‑002 SHALL** The kernel support atomic configuration updates (rollback on failure).

---

## 15. Security Architecture

### 15.1. Cryptographic Boundaries

| Secret/Key | Storage | Access | Notes |
|------------|---------|--------|-------|
| CAPKs (public keys) | Signed configuration blob, integrity‑protected | Kernel reads via configuration parser | No confidentiality needed |
| Issuer master keys | Not in kernel | – | Issuer side only |
| ARQC/ARPC | Not generated or stored | Kernel passes through | Transient |
| PIN block | PED only | Kernel receives only handle or status | Never clear in kernel |
| Unpredictable number | Generated by terminal (call `get_unpredictable_number()`) | Kernel uses as APDU data | Should be random |

**KRN‑SEC‑005 SHALL** The kernel never store, copy, or modify a PIN block. The PIN callback returns a `krn_pin_result_t` that contains:

```c
typedef struct {
    krn_pin_status_t status; // SUCCESS, FAILURE, TRY_LIMIT_EXCEEDED
    uint8_t try_remain;
    krn_secure_handle_t encrypted_pin_handle; // for online PIN
    size_t pin_block_len;
} krn_pin_result_t;
```

The kernel does not dereference the handle; it passes it to the host interface.

### 15.2. Logging and Data Masking

**KRN‑LOG‑001 SHALL** The kernel produce a structured log for each transaction with the following mandatory masking:

| Data type | Masking rule |
|-----------|--------------|
| PAN | Keep only last 4 digits; all other digits replaced with `*` |
| Track 2 equivalent data | Never log, only hash for debugging (opt‑in) |
| PIN block | Never log |
| ARQC/ARPC | May be logged in debug mode only with `#ifdef DEBUG` not present in production |
| APDU logs (full) | Configurable; disabled in production unless certified support mode |
| Crash dumps | Must exclude all cardholder data and keys |

**KRN‑LOG‑002 SHALL** The kernel provide a callback `log_event()` that the terminal application implements with appropriate level and masking.

### 15.3. PCI PTS Alignment

The kernel does not need PCI PTS certification by itself, but must be integrated with a PCI PTS‑approved PED. Integration requirements:

- Kernel never receives plain PIN.
- Online PIN block is passed as a secure reference, not raw bytes.
- Kernel does not modify the encrypted PIN block length or content.

---

## 16. API / ABI Specification

The kernel exposes a C API (ABI stable). All functions return `emv_status_t`.

### 16.1. Initialisation

```c
typedef struct {
    uint32_t abi_version;          // must be KRN_ABI_VERSION
    uint32_t struct_size;          // sizeof(krn_runtime_t)
    krn_callbacks_t callbacks;
    krn_allocator_t allocator;     // optional, use malloc/free if NULL
    krn_timeouts_t timeouts;       // in milliseconds
    krn_log_policy_t log_policy;
} krn_runtime_t;

emv_status_t krn_init(const krn_config_blob_t *cfg, 
                      const krn_runtime_t *runtime,
                      krn_handle_t *out_kernel);
```

### 16.2. Transaction Parameters

```c
typedef struct {
    uint64_t amount_authorised;    // in minor units
    uint64_t amount_other;         // cashback, etc.
    uint16_t currency_code;        // ISO numeric
    uint8_t transaction_type;      // EMV defined
    uint8_t terminal_type;
    uint8_t merchant_category_code[2];
    // ... other fields
} krn_txn_params_t;

emv_status_t krn_set_transaction_params(krn_handle_t kernel, const krn_txn_params_t *params);
```

### 16.3. Callbacks (Level 3 must implement)

```c
typedef struct {
    // APDU transport (contact/contactless)
    int (*transmit_apdu)(const uint8_t *cmd, size_t cmd_len, 
                         uint8_t *resp, size_t *resp_len, int timeout_ms);
    
    // PIN entry
    krn_pin_result_t (*request_pin)(int online, int max_len, int *try_remain);
    
    // UI messages
    void (*display_message)(const char *msg, int error, int duration_ms);
    
    // Host authorisation
    int (*send_online_request)(const uint8_t *data, size_t len,
                               uint8_t *response, size_t *resp_len, int timeout_ms);
    
    // Unpredictable number (random)
    int (*get_unpredictable_number)(uint8_t *un, size_t len);
    
    // Logging
    void (*log_event)(int level, const char *fmt, ...);
    
    // Contactless outcome parameter set (UI requests)
    void (*contactless_outcome)(uint8_t outcome_code, const char *ui_message);
} krn_callbacks_t;
```

**KRN‑API‑001 SHALL** The kernel be callable from a single thread only; no re‑entrancy.  
**KRN‑API‑002 SHALL** All buffers passed to callbacks are owned by the caller; the kernel does not free them.

### 16.4. Running the Transaction

```c
typedef enum {
    KRN_OUTCOME_APPROVED_OFFLINE,
    KRN_OUTCOME_DECLINED_OFFLINE,
    KRN_OUTCOME_GO_ONLINE,          // kernel will request host
    KRN_OUTCOME_APPROVED_ONLINE,
    KRN_OUTCOME_DECLINED_ONLINE,
    KRN_OUTCOME_TRY_AGAIN,
    KRN_OUTCOME_TERMINATED
} krn_outcome_t;

krn_outcome_t krn_run_transaction(krn_handle_t kernel);
```

### 16.5. Error Codes

| Code | Meaning |
|------|---------|
| `KRN_OK` | Success |
| `KRN_ERR_INVALID_STATE` | API called out of order |
| `KRN_ERR_CARD_REMOVED` | Card removed during transaction |
| `KRN_ERR_MISSING_MANDATORY_TAG` | Required TLV missing |
| `KRN_ERR_ODA_FAILED` | Offline data authentication failure |
| `KRN_ERR_CVM_FAILED` | Cardholder verification failed |
| `KRN_ERR_HOST_TIMEOUT` | Online authorisation timeout |
| `KRN_ERR_SCRIPT_FAILED` | Issuer script execution failure |
| `KRN_ERR_CONFIG_INVALID` | Configuration invalid or expired |
| `KRN_ERR_NO_COMMON_AID` | No supported application on card |

**KRN‑API‑003 SHALL** All error codes be documented and stable across versions.

---

## 17. Performance and Resource Model

The kernel shall meet the following performance targets, depending on deployment tier:

| Tier | Target Device | Code+Static Data | Transaction Context | Contact Execution (kernel only) | Contactless Execution (kernel only) |
|------|---------------|------------------|---------------------|--------------------------------|-------------------------------------|
| **A** | Cortex‑M / RTOS | ≤ 256 KB | ≤ 4 KB | ≤ 80 ms | ≤ 40 ms |
| **B** | Linux embedded | ≤ 1 MB | ≤ 32 KB | ≤ 60 ms | ≤ 30 ms |
| **C** | Android POS | no hard limit | no hard limit | performance‑bound (aim ≤ 50 ms) | performance‑bound (aim ≤ 25 ms) |

**KRN‑PERF‑001 SHALL** The kernel be optimised for deterministic execution; worst‑case ODA (RSA‑2048) may exceed the above budget but must be bounded.

---

## 18. Testing and Certification Evidence

### 18.1. Testing Requirements

| Test Level | Scope | Coverage Target |
|------------|-------|-----------------|
| Unit | Each function (TLV, APDU builder, TVR/TSI, state machine) | ≥95% branch coverage |
| Integration | Full transaction with simulated card (APDU script replay) | 100% of EMV test plan for each scheme |
| Fuzz | APDU parser, TLV parser, configuration parser | 1 million iterations, no crash/memory leak |
| Simulator | Run EMVCo test tool (e.g., Fime Eval4dev) | Pass all relevant test cases for target schemes |

### 18.2. Certification Evidence Matrix

| Artifact | Description | Format | Required by |
|----------|-------------|--------|-------------|
| Conformance statement | Mapping of kernel functions to EMV requirements | Spreadsheet | Lab |
| Configuration manifest | AID list, CAPKs, TACs, IACs, limits for each scheme | JSON + signature | Lab |
| Trace logs (masked) | Full APDU exchange for every test case | PCAP or structured JSON | Lab |
| Unit test report | Coverage, pass/fail, environment | HTML/XML | Internal |
| Static analysis report | MISRA C (or equivalent) compliance | Report | Lab (depending) |
| Fuzzing report | No crashes or memory leaks | Log | Internal |
| PCI PTS integration statement | How kernel separates PIN handling | Document | Lab, acquirer |
| Lab submission pack | All above, plus device under test, test harness | Archive | EMVCo laboratory |

**KRN‑CERT‑001 SHALL** The kernel achieve EMVCo Level 2 certification for each claimed scheme and interface (contact, contactless, C‑8).  
**KRN‑CERT‑002 SHOULD** The kernel pass a third‑party penetration test focused on APDU injection and state machine bypass.

---

## 19. Deployment and Updates

**KRN‑DPL‑001 SHALL** The kernel support over‑the‑air (OTA) configuration updates (CAPK renewal, TAC changes, new AIDs) using signed, versioned configuration packages.  
**KRN‑DPL‑002 SHALL** The kernel implement rollback protection: reject any configuration with a version number lower than the current installed version, unless forced by a signed override.  
**KRN‑DPL‑003 SHALL** The kernel maintain a non‑volatile counter (or use secure storage) to enforce update freshness.

---

## 20. Contactless / C‑8 Annex

### 20.1. Entry Point Processing

For contactless transactions, the kernel shall follow the EMV Contactless Kernel Specification Book C‑8:

- Perform PPSE SELECT using the entry point `2PAY.SYS.DDF01`.
- Parse the FCI to obtain a list of candidate AIDs.
- Select the highest priority AID that matches the terminal’s configuration.
- Activate the C‑8 kernel (or scheme‑specific kernel) for the remainder of the transaction.

### 20.2. C‑8 Outcome Parameter Set

The C‑8 kernel must return a structured outcome that includes:

| Field | Values | Description |
|-------|--------|-------------|
| `outcome_code` | `APPROVED`, `DECLINED`, `ONLINE_REQUIRED`, `TRY_AGAIN`, `SELECT_NEXT`, `ALTERNATE_INTERFACE` | Determines terminal action |
| `ui_message_id` | enumerated (e.g., `PRESENT_CARD`, `REMOVE_CARD`, `SEE_PHONE`) | Display message to cardholder |
| `hold_time` | milliseconds | Minimum time to keep message |
| `restart` | boolean | Whether to restart kernel |

**KRN‑C8‑001 SHALL** The kernel implement the C‑8 outcome parameter handling via the `contactless_outcome()` callback.

### 20.3. C‑8 Limits and CVM

- Contactless transaction limit (CTL): configured per scheme.
- Contactless CVM limit (CCL): configured per scheme.
- CDCVM verification: shall be accepted if the card indicates CDCVM performed.

### 20.4. Relay / Resistance

If the card supports relay resistance (e.g., with a distance bounding or latency checks), the kernel shall support the required APDUs and timing constraints. This is optional but recommended.

### 20.5. Coexistence with Legacy Kernels

The terminal may contain both C‑8 and legacy scheme kernels. The kernel selection logic (signed configuration) shall determine which kernel is used per AID and interface.

---

## Appendices

### Appendix A – Complete TLV Catalogue (CSV format)

(Provided as a separate machine‑readable file with columns: Tag, Name, Format, Presence, Source, Scheme.)

### Appendix B – APDU Command Summary Table

| Command | CLA | INS | P1 | P2 | Data | Le | Response |
|---------|-----|-----|----|----|------|----|----------|
| SELECT (DF) | `00` | `A4` | `04` | `00` | AID | `00` | FCI |
| SELECT (PSE) | `00` | `A4` | `04` | `00` | `2PAY.SYS.DDF01` | `00` | FCI |
| GPO | `80` | `A8` | `00` | `00` | PDOL | `00` | `77` / `80` |
| READ RECORD | `00` | `B2` | rec | SFI\|`04` | – | `00` | Record |
| INTERNAL AUTH | `00` | `88` | `00` | `00` | DDOL | `00` | Signature |
| VERIFY (offline PIN) | `00` | `20` | `00` | `00` | PIN block | – | `90 00` / `63 CX` |
| GENERATE AC (1st) | `80` | `AE` | type | `00` | CDOL1 | `00` | Cryptogram |
| GENERATE AC (2nd) | `80` | `AE` | `00` | `00` | CDOL2 | `00` | Cryptogram |
| EXTERNAL AUTH | `00` | `82` | `00` | `00` | ARPC | – | `90 00` |

### Appendix C – Test Vectors for ODA

(Example CAPKs, issuer certificates, ICC certificates, and expected TVR bits. To be provided in a separate document.)

### Appendix D – Trace Log Format Specification

```json
{
  "transaction_id": "hex-string",
  "timestamp": "ISO8601",
  "kernel_version": "1.0",
  "scheme": "Visa",
  "interface": "contactless",
  "outcome": "APPROVED_OFFLINE",
  "apdus": [
    { "direction": "cmd", "apdu": "00A404000E325041592E5359532E444446303100", "sw": null },
    { "direction": "resp", "apdu": "6F...", "sw": "9000" }
  ],
  "tvr": "0000000000",
  "tsi": "0000"
}
```

All PANs and track data masked (only last 4 digits of PAN shown).

### Appendix E – Full State Machine Transition Table

(Provided as a separate CSV file mapping current state, event, guard, next state, action, error code.)

### Appendix F – Scheme Profile Examples (Visa, Mastercard, C‑8)

(Detailed JSON profiles with all required TACs, IACs, limits, and AID configurations.)

---

**End of Specification v3.0**