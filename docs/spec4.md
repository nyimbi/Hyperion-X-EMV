# EMV Level 2 Kernel Specification – Hyperion Kernel (Hyperion‑KRN) – v4.0

**Version:** 4.0  
**Status:** Normative implementation and certification baseline  
**Target EMV Baseline:** EMV Contact Chip Specifications Book 3 v4.4 (and Book 1, 2, 4 where referenced)  
**Contactless Baseline:** EMV Contactless Kernel Specification Book C‑8 v1.0  
**PCI Baseline:** PCI PTS POI v7.0  
**Document Control:** This specification is normative for all engineering, testing, and certification activities related to the Hyperion EMV kernel.

---

## 1. Scope and Normative References

### 1.1 Scope

This document defines the **behaviour, interfaces, configuration, testing, and certification requirements** of the Hyperion EMV Level 2 kernel (hereinafter “the kernel”). The kernel executes EMV transaction logic for contact (ISO7816) and contactless (ISO14443) payment cards, but **does not** implement:

- Physical or electrical card interface (Level 1)
- PIN capture or secure PIN entry device (PED) logic
- Host (acquirer, issuer) authorisation messaging
- Issuer master key custody or cryptogram validation (except CAPKs for offline data authentication)

### 1.2 Normative References

| ID | Reference | Version | Applicability |
|---|---|---|---|
| **[EMV4.4]** | EMV Contact Chip Specifications – Books 1‑4 | v4.4 | Core contact logic |
| **[EMV4.3]** | EMV Contact Chip Specifications – Books 1‑4 | v4.3 | Legacy compatibility floor |
| **[C8]** | EMV Contactless Specifications for Payment Systems – Book C‑8 (Kernel 8) | v1.0 | Contactless unified kernel |
| **[EMVCo L2]** | EMV Level 2 Approval Process | current | Certification process |
| **[PCI PTS]** | PCI PIN Transaction Security POI Modular Requirements | v7.0 | PIN handling alignment |
| **[ISO7816‑3]** | Identification cards – Integrated circuit cards – Part 3 | latest | T=0/T=1 protocol |
| **[ISO7816‑4]** | Interindustry commands for interchange | latest | APDU structure |
| **[ISO14443‑4]** | Contactless – Part 4: Transmission protocol | latest | Contactless APDU |
| **[ISO9564‑1]** | PIN block formats | latest | Online PIN encryption |

> **KRN‑REF‑001**: The implementation **SHALL** comply with all normative references. In case of conflict between references and this specification, the referenced standards prevail.

---

## 2. Trust Boundary and Responsibility Model

The kernel is one component inside a payment acceptance system. The following table defines ownership boundaries:

| Component | Responsibilities | Owned by | Security classification |
|---|---|---|---|
| **EMV L2 kernel** | CAPK integrity checks; ODA (SDA, DDA, CDA); APDU orchestration; TVR/TSI setting; CDOL/DDOL construction; cryptogram response parsing; final decision (offline approve/decline/go online) | Hyperion kernel | Integrity‑critical, no confidentiality for CAPKs |
| **Secure PIN subsystem (PED)** | PIN capture, PIN block formatting (ISO9564‑1), online PIN encryption (DUKPT), offline plaintext PIN VERIFY APDU handling. PCI PTS certified. | Terminal manufacturer / kernel integrator | Confidentiality‑critical |
| **Level 3 application** | UI, host communication, scripting environment, receipt printing | Terminal application developer | Functional |
| **Acquirer / switch** | ISO 8583/ISO 20022 routing, authorisation request forwarding | Acquirer | Functional |
| **Issuer / issuer processor** | Issuer master keys, ARQC validation, ARPC generation, issuer scripts | Issuer | Confidentiality‑critical |

> **KRN‑SEC‑001**: No issuer master key **SHALL** be stored or accessible inside the kernel.  
> **KRN‑SEC‑002**: The kernel **SHALL NOT** generate ARQC, TC, or AAC; these cryptograms are returned by the card in response to GENERATE AC.  
> **KRN‑SEC‑003**: CAPKs are **public keys**; they require integrity protection and authenticity but **not confidentiality**. They may be stored in plaintext with a digital signature covering the configuration blob.  
> **KRN‑SEC‑004**: PIN processing **SHALL** be delegated to a PCI PTS‑approved PED module. The kernel receives only a **secure handle** to an encrypted PIN block (for online) or a success/failure status (for offline). The kernel never accesses the clear PIN.

---

## 3. Application Selection – Contact PSE and Contactless PPSE

The kernel MUST correctly differentiate between contact and contactless environments:

| Environment | DF name | Command | Notes |
|---|---|---|---|
| **Contact PSE** | `1PAY.SYS.DDF01` | `00 A4 04 00 0E 31 50 41 59 2E 53 59 53 2E 44 44 46 30 31 00` (15 bytes, right‑padded with `0F`? **Spec uses 15‑byte right‑padded by `0F`**). **Spec may expect 14‑byte `2PAY...` or 15‑byte padded `1PAY...`. Execution path to be determined by device type.** | First step in contact card processing (PSE) |
| **Contactless PPSE** | `2PAY.SYS.DDF01` | `00 A4 04 00 0E 32 50 41 59 2E 53 59 53 2E 44 44 46 30 31 00` | Used for contactless NFC cards to read the PPSE |

> **KRN‑SEL‑001**: The kernel **SHALL** select the PSE using `1PAY.SYS.DDF01` for contact cards and the PPSE using `2PAY.SYS.DDF01` for contactless cards.

---

## 4. Data Objects Dictionary

### 4.1 Mandatory EMV Tags (Normative subset)

| Tag | Name | Format | Presence | Source | Scheme |
|---|---|---|---|---|---|
| `4F` | AID | Primitive, variable | Mandatory | EMV Book 3 | All |
| `50` | Application Label | Primitive, variable | Recommended | EMV Book 3 | All |
| `57` | Track 2 Equivalent Data | Primitive, variable | Mandatory | EMV Book 3 | All |
| `5A` | PAN | Primitive, variable | Mandatory | EMV Book 3 | All |
| `5F24` | Application Expiration Date | Primitive, 3 bytes | Mandatory | EMV Book 3 | All |
| `5F2A` | Transaction Currency Code | Primitive, 2 bytes | Mandatory (terminal) | EMV Book 3 | All |
| `82` | AIP | Primitive, 2 bytes | Mandatory after GPO | EMV Book 3 | All |
| `84` | DF Name (PPSE) | Primitive, variable | Contactless | EMV Contactless | All |
| `8C` | CDOL1 | Data Object List (tag‑length pairs) | If present | EMV Book 3 | All |
| `8D` | CDOL2 | Data Object List (tag‑length pairs) | If present | EMV Book 3 | All |
| `8E` | CVM List | Constructed | Mandatory | EMV Book 3 | All |
| `91` | Issuer Authentication Data | Primitive, variable | For ARPC | EMV Book 3 | All |
| `94` | AFL | Primitive, variable | Mandatory after GPO | EMV Book 3 | All |
| `95` | TVR | Primitive, 5 bytes | Kernel sets | EMV Book 3 | All |
| `9A` | Transaction Date | Primitive, 3 bytes | Terminal sets | EMV Book 3 | All |
| `9B` | TSI | Primitive, 2 bytes | Kernel sets | EMV Book 3 | All |
| `9C` | Transaction Type | Primitive, 1 byte | Terminal sets | EMV Book 3 | All |
| `9F02` | Amount Authorised (numeric) | Primitive, 6 bytes | Terminal sets | EMV Book 3 | All |
| `9F07` | Application Usage Control | Primitive, 2 bytes | Mandatory | EMV Book 3 | All |
| `9F09` | Application Version Number | Primitive, 2 bytes | Mandatory | EMV Book 3 | All |
| `9F10` | Issuer Application Data | Primitive, variable | Mandatory for host | EMV Book 3 | All |
| `9F1A` | Terminal Country Code | Primitive, 2 bytes | Terminal sets | EMV Book 3 | All |
| `9F26` | Application Cryptogram | Primitive, 8 bytes | From card | EMV Book 3 | All |
| `9F27` | CID (Cryptogram Information Data) | Primitive, 1 byte | From card | EMV Book 3 | All |
| `9F33` | Terminal Capabilities | Primitive, 3 bytes | Terminal sets | EMV Book 3 | All |
| `9F34` | CVM Results | Primitive, 3 bytes | Kernel sets | EMV Book 3 | All |
| `9F35` | Terminal Type | Primitive, 1 byte | Terminal sets | EMV Book 3 | All |
| `9F36` | ATC (Application Transaction Counter) | Primitive, 2 bytes | From card | EMV Book 3 | All |
| `9F37` | Unpredictable Number | Primitive, 4 bytes | Terminal generates | EMV Book 3 | All |
| `9F4C` | ICC Dynamic Number | Primitive, variable | For CDA | EMV Book 3 | All |
| `9F4E` | Merchant Category Code | Primitive, 2 bytes | Terminal sets | EMV Book 3 | All |
| `9F6C` | CTQ | Primitive, 1 byte | For contactless | EMV Contactless | All |
| `9F66` | TTQ | Primitive, 4 bytes | For contactless | EMV Contactless | All |

---

## 5. Transaction Status and Verification Results

### 5.1 Terminal Verification Results (TVR) – 5‑byte bit array

The TVR records the results of risk and compliance checks performed by the terminal. Each bit is defined as follows:

| Byte | Bit | EMV condition | Set by | Symbolic constant (example) |
|---|---|---|---|---|
| 1 | b8 (high) | Offline data authentication was not performed | ODA engine | `TVR_B1_OFFLINE_DATA_AUTH_NOT_PERFORMED` |
| 1 | b7 | SDA failed | ODA engine | `TVR_B1_SDA_FAILED` |
| 1 | b6 | ICC data missing | TLV validator | `TVR_B1_ICC_DATA_MISSING` |
| 1 | b5 | Card appears on terminal exception file | Terminal risk mgmt | `TVR_B1_CARD_ON_EXCEPTION_FILE` |
| 1 | b4 | DDA failed | ODA engine | `TVR_B1_DDA_FAILED` |
| 1 | b3 | CDA failed | ODA engine | `TVR_B1_CDA_FAILED` |
| 1 | b2‑b1 | RFU | – | – |
| 2 | b8 (high) | ICC and terminal have different application versions | Processing restrictions | `TVR_B2_APP_VERSION_MISMATCH` |
| 2 | b7 | Expired application | Processing restrictions | `TVR_B2_APP_EXPIRED` |
| 2 | b6 | Application not yet effective | Processing restrictions | `TVR_B2_APP_NOT_EFFECTIVE` |
| 2 | b5 | Requested service not allowed for card product | Processing restrictions | `TVR_B2_SERVICE_NOT_ALLOWED` |
| 2 | b4 | New card | Processing restrictions / card data | `TVR_B2_NEW_CARD` |
| 2 | b3‑b1 | RFU | – | – |
| 3 | b8 (high) | Cardholder verification was not successful | CVM module | `TVR_B3_CVM_FAILED` |
| 3 | b7 | Unrecognised CVM | CVM module | `TVR_B3_UNRECOGNISED_CVM` |
| 3 | b6 | PIN try limit exceeded | CVM module (from VERIFY response) | `TVR_B3_PIN_TRY_LIMIT_EXCEEDED` |
| 3 | b5 | PIN entry required and PIN pad not present or not working | CVM module | `TVR_B3_PIN_PAD_NOT_PRESENT` |
| 3 | b4 | PIN entry required, PIN pad present, but PIN not entered | CVM module | `TVR_B3_PIN_NOT_ENTERED` |
| 3 | b3 | Online PIN entered | CVM module | `TVR_B3_ONLINE_PIN_ENTERED` |
| 3 | b2‑b1 | RFU | – | – |
| 4 | b8 (high) | Transaction exceeds floor limit | TRM | `TVR_B4_EXCEEDS_FLOOR_LIMIT` |
| 4 | b7 | Lower consecutive offline limit exceeded | TRM | `TVR_B4_LOWER_CONSECUTIVE_OFFLINE_LIMIT` |
| 4 | b6 | Upper consecutive offline limit exceeded | TRM | `TVR_B4_UPPER_CONSECUTIVE_OFFLINE_LIMIT` |
| 4 | b5 | Transaction selected for random force online | TRM | `TVR_B4_RANDOM_SELECTION` |
| 4 | b4‑b1 | RFU | – | – |
| 5 | ... | Merchant / scheme specific | – | – |

> **KRN‑TVR‑001**: The kernel **SHALL** use the symbolic constants above when setting TVR bits; raw hex constants **SHALL NOT** be used directly in code without a mapping layer.  
> **KRN‑TVR‑002**: The kernel **SHALL** clear TVR before each transaction.

### 5.2 Transaction Status Information (TSI) – 2‑byte bit array

The TSI records which EMV processing steps have been performed:

| Byte | Bit | Condition | Set by | Symbolic constant (example) |
|---|---|---|---|---|
| 1 | b8 (high) | Offline data authentication performed | ODA engine | `TSI_B1_ODA_PERFORMED` |
| 1 | b7 | Cardholder verification performed | CVM module | `TSI_B1_CVM_PERFORMED` |
| 1 | b6 | Card risk management performed | Card (from AIP) | – |
| 1 | b5 | Issuer authentication performed | Kernel after online response | `TSI_B1_ISSUER_AUTH_PERFORMED` |
| 1 | b4 | Terminal risk management performed | TRM engine | `TSI_B1_TRM_PERFORMED` |
| 1 | b3 | Script processing performed | Script processor | `TSI_B1_SCRIPT_PROCESSING_PERFORMED` |
| 1 | b2‑b1 | RFU | – | – |
| 2 | ... | Reserved for future use (RFU) | – | – |

> **KRN‑TSI‑001**: The kernel **SHALL** set TSI bits accordingly after each processing phase.

### 5.3 Cryptogram Information Data (CID) – Tag `9F27`, 1 byte

| Bits 7‑6 | Meaning | Action |
|---|---|---|
| 00 | AAC (Application Authentication Cryptogram) | Offline decline |
| 01 | TC (Transaction Certificate) | Offline approval |
| 10 | ARQC (Authorization Request Cryptogram) | Go online |
| 11 | AAR / referral or reserved according to scheme profile | Follow scheme‑specific rules |

> **KRN‑CID‑001**: The kernel **SHALL** decode CID bits 7‑6 as per the table above. Other bits (5‑0) **SHALL** be ignored for cryptogram type determination but preserved for logging.

**Implementation code (C):**
```c
typedef enum {
    KRN_CRYPTOGRAM_AAC = 0,
    KRN_CRYPTOGRAM_TC  = 1,
    KRN_CRYPTOGRAM_ARQC = 2,
    KRN_CRYPTOGRAM_AAR = 3,
    KRN_CRYPTOGRAM_RESERVED = 4
} krn_cryptogram_type_t;

krn_cryptogram_type_t krn_decode_cid(uint8_t cid) {
    uint8_t type_bits = (cid >> 6) & 0x03;
    switch (type_bits) {
        case 0: return KRN_CRYPTOGRAM_AAC;
        case 1: return KRN_CRYPTOGRAM_TC;
        case 2: return KRN_CRYPTOGRAM_ARQC;
        case 3: return KRN_CRYPTOGRAM_AAR;
        default: return KRN_CRYPTOGRAM_RESERVED;
    }
}
```

---

## 6. Offline PIN and Online PIN Handling

The kernel **MUST** distinguish between three PIN modalities with clear trust boundaries:

| PIN mode | Correct handling boundary | Kernel responsibility |
|---|---|---|
| **Plaintext offline PIN** | PED captures PIN securely; kernel constructs VERIFY APDU **without encryption**; sends to card; PED interacts only with card trust boundary | Build APDU, send, parse response |
| **Enciphered offline PIN** | PIN block is enciphered using ICC public key mechanism; PED/secure module constructs enciphered PIN block; kernel forwards APDU | Pass‑through only |
| **Online PIN** | PED creates encrypted PIN block (often under DUKPT or other acquirer‑approved scheme); kernel passes secure handle to L3 for host message; kernel never touches plaintext or encrypted PIN | Handle reference only |

> **KRN‑CVM‑001**: The kernel **SHALL NOT** construct, modify, or access any PIN block in clear text. The kernel **SHALL** receive a **secure handle** to an encrypted PIN block (for online) or a success/failure status (for plaintext offline).  
> **KRN‑CVM‑002**: The kernel **SHALL** implement the `request_pin()` callback returning a `krn_pin_result_t` structure containing a `krn_secure_handle_t` (for online) and the remaining PIN try counter.

```c
typedef enum {
    KRN_PIN_STATUS_SUCCESS,
    KRN_PIN_STATUS_FAILURE,
    KRN_PIN_STATUS_TRY_LIMIT_EXCEEDED
} krn_pin_status_t;

typedef struct {
    krn_pin_status_t status;
    uint8_t try_remain;
    krn_secure_handle_t encrypted_pin_handle; // for online PIN, otherwise NULL
    size_t pin_block_len;                     // for online PIN
} krn_pin_result_t;
```

---

## 7. APDU Command Handling and SW1/SW2 Processing

The kernel must handle a broader class of APDU status words beyond `90 00` and `63 CX`:

| SW1/SW2 | Meaning | Action |
|---|---|---|
| `90 00` | Normal processing – success | Continue to next state |
| `61xx` | More data available (xx bytes) | Issue GET RESPONSE |
| `6Cxx` | Correct Le expected length | Re‑send command with correct Le |
| `6985` | Conditions of use not satisfied | Treat as error, set TVR accordingly |
| `6A82` | File/application not found | Fallback or termination |
| `6A83` | Record not found | End of record reading |
| `6283` | Selected file invalidated, context‑dependent | Evaluate scheme rules |
| `63Cx` | VERIFY warning with (x) remaining tries | Set `PIN_TRY_LIMIT_EXCEEDED` if x == 0 |

> **KRN‑APDU‑009**: The kernel **SHALL** handle all the above APDU status words as specified. Implementation **SHALL NOT** collapse all non‑`9000` responses into a generic error.

---

## 8. GENERATE AC P1 Encoding

The terminal requests a cryptogram type by setting P1 as follows:

| Requested cryptogram | P1 value | Description |
|---|---|---|
| AAC (Offline decline) | `0x00` | Application Authentication Cryptogram |
| TC (Offline approval) | `0x40` | Transaction Certificate |
| ARQC (Go online) | `0x80` | Authorization Request Cryptogram |
| CDA request | Bit‑mask as per EMV Book 3 | Combine with cryptogram type bits |

> **KRN‑GAC‑008**: The kernel **SHALL** encode P1 for GENERATE AC as per the table above. The high‑order bit (`0x80`) indicates a request for ARQC, not a generic “first GENERATE AC” flag.  
> **KRN‑GAC‑009**: If CDA is supported and the kernel is performing CDA, the kernel **SHALL** set additional P1 bits according to EMV Book 3.

---

## 9. Cardholder Verification (CVM) Methods

The kernel supports the following CVM methods as defined in EMV Book 3:

| Method code | Method | Handling |
|---|---|---|
| `01` | Offline plaintext PIN | Call `request_pin(offline, ...)`; send VERIFY APDU; do **not** encrypt PIN block |
| `02` | Online PIN | Call `request_pin(online, ...)`; receive secure handle; pass to host in online request |
| `03` | Signature | (If permitted) call `notify_signature_required()`; set TVR if not performed |
| `04` | No CVM | Accept if amount ≤ CVM limit |
| `05` | CDCVM | Check consumer device CVM flag (from card or terminal); treat as successful CVM |

> **KRN‑CVM‑003**: The kernel **SHALL** enforce CVM limits per scheme. If a method exceeds the allowed amount limit, that method is considered failed.  
> **KRN‑CVM‑004**: After CVM evaluation, the kernel **SHALL** set TVR bits (byte 3) accordingly.

---

## 10. Terminal Action Analysis (TAA) – Full Decision Table

The kernel **MUST** apply **both** Terminal Action Codes (TAC) and Issuer Action Codes (IAC) in the following order:

| Step | Action |
|---|---|
| 1 | Check `(TVR & (IAC_Denial | TAC_Denial)) != 0`. If **true**, request AAC (offline decline). |
| 2 | Else, check `terminal_online_capable` and `(TVR & (IAC_Online | TAC_Online)) != 0`. If **true**, request ARQC (online). |
| 3 | Else, check `!terminal_online_capable` and `(TVR & (IAC_Default | TAC_Default)) != 0`. If **true**, request AAC (decline) or TC per scheme fallback policy. |
| 4 | Else, request TC (offline approval) or ARQC according to scheme/application profile. |

### 10.1 IAC and TAC Definitions

- **IAC (Issuer Action Codes)**: Read from the card’s records; three 5‑byte values:
  - `IAC_Denial`: bits that cause offline decline
  - `IAC_Online`: bits that cause online request
  - `IAC_Default`: bits that cause decline when online is unavailable
- **TAC (Terminal Action Codes)**: Three 5‑byte values (Denial, Online, Default) loaded into terminal configuration.

> **KRN‑TAA‑004**: The kernel **SHALL** fetch IACs from the card’s application records.  
> **KRN‑TAA‑005**: The kernel **SHALL** fetch TACs from its signed configuration (per scheme and per AID).  
> **KRN‑TAA‑006**: The kernel **SHALL** evaluate the decision steps in the exact order listed. The “default cryptogram” **SHALL NOT** be a free configuration value without constraints.

---

## 11. Contactless / C‑8 Annex

The kernel **SHALL** implement the EMV Contactless Kernel Specification Book C‑8 (Kernel 8) for all contactless transactions where supported.

- **Entry Point**: Use `2PAY.SYS.DDF01` (PPSE) for application selection.  
- **Outcome parameters**: After transaction completion, the C‑8 kernel must return a structured outcome containing:
  - `outcome_code` (APPROVED, DECLINED, ONLINE_REQUIRED, TRY_AGAIN, SELECT_NEXT, ALTERNATE_INTERFACE)
  - `ui_message_id` (PRESENT_CARD, REMOVE_CARD, SEE_PHONE)
  - `hold_time` (milliseconds)
  - `restart` (boolean)

- **Limits**: Support CTL (contactless transaction limit) and CCL (contactless CVM limit) from terminal configuration.
- **Relay resistance**: Where the card supports relay resistance protocols, the C‑8 kernel **SHALL** support the required APDUs and timing constraints.

> **KRN‑C8‑001**: The kernel **SHALL** implement C‑8 unified kernel for contactless transactions.  
> **KRN‑C8‑002**: The kernel **SHALL** return outcome parameters via the `contactless_outcome()` callback.  
> **KRN‑C8‑003**: The kernel **SHALL NOT** treat C‑8 as a contact kernel replacement; contact transactions **SHALL** use contact EMV L2 kernels.

---

## 12. CDOL1 and CDOL2 – Encoding of Data Object Lists

CDOL1 and CDOL2 are **Data Object Lists (DOLs)** – sequences of **tag‑length pairs** without value bytes. The kernel **SHALL** parse these DOLs and construct the data field for GENERATE AC by concatenating the actual values of each referenced tag **in the order defined**.

**Example CDOL1 encoding (4 bytes of tag‑length data)**:

```
Tag 9F02 (2 bytes) + length 06  
Tag 9A (2 bytes) + length 03  
Tag 5F2A (2 bytes) + length 02  
Tag 9F37 (2 bytes) + length 04
```

> **KRN‑DOL‑001**: The kernel **SHALL** parse DOLs as sequences of tag‑length pairs.  
> **KRN‑DOL‑002**: The kernel **SHALL NOT** interpret DOLs as constructed BER‑TLV templates.

---

## 13. API / ABI Specification

The kernel exposes a C API (ABI stable). All functions return `emv_status_t`.

```c
typedef enum {
    KRN_OUTCOME_APPROVED_OFFLINE,
    KRN_OUTCOME_DECLINED_OFFLINE,
    KRN_OUTCOME_GO_ONLINE,
    KRN_OUTCOME_APPROVED_ONLINE,
    KRN_OUTCOME_DECLINED_ONLINE,
    KRN_OUTCOME_TRY_AGAIN,
    KRN_OUTCOME_TERMINATED
} krn_outcome_t;
```

### 13.1 Initialisation

```c
typedef struct {
    uint32_t abi_version;
    uint32_t struct_size;
    krn_callbacks_t callbacks;
    krn_allocator_t allocator;
    krn_timeouts_t timeouts;
    krn_log_policy_t log_policy;
} krn_runtime_t;

emv_status_t krn_init(const krn_config_blob_t *cfg,
                      const krn_runtime_t *runtime,
                      krn_handle_t *out_kernel);
```

### 13.2 Callbacks

```c
typedef struct {
    int (*transmit_apdu)(const uint8_t *cmd, size_t cmd_len,
                         uint8_t *resp, size_t *resp_len, int timeout_ms);
    krn_pin_result_t (*request_pin)(int online, int max_len, int *try_remain);
    void (*display_message)(const char *msg, int error, int duration_ms);
    int (*send_online_request)(const uint8_t *data, size_t len,
                               uint8_t *response, size_t *resp_len, int timeout_ms);
    int (*get_unpredictable_number)(uint8_t *un, size_t len);
    void (*log_event)(int level, const char *fmt, ...);
    void (*contactless_outcome)(uint8_t outcome_code, const char *ui_message);
} krn_callbacks_t;
```

> **KRN‑API‑004**: The kernel **SHALL NOT** be re‑entrant; the caller **SHALL** serialise calls to a single kernel instance.  
> **KRN‑API‑005**: All buffers passed to callbacks are owned by the caller; the kernel **SHALL NOT** free them.

---

## 14. Security Architecture

### 14.1 Cryptographic Boundaries

- **CAPKs**: integrity‑protected public keys; confidentiality **not required**.  
- **Issuer master keys**: **not** stored or accessed by the kernel.  
- **ARQC/ARPC**: not generated or validated by the kernel; only passed through.  
- **PIN block**: kernel receives only a **secure handle** from the PED.  
- **Unpredictable number**: generated by kernel using hardware random source.

### 14.2 Logging and Data Masking

| Data type | Masking rule |
|---|---|
| PAN | Keep only last 4 digits; replace all other digits with `*` |
| Track 2 equivalent data | Never log |
| PIN block | Never log |
| ARQC/ARPC | May be logged in debug mode only with `#ifdef DEBUG` **not** in production |
| Full APDU logs | Configurable; disabled in production unless certified support mode |

---

## 15. Performance and Resource Model

The kernel **SHALL** meet the following performance and memory constraints (target tier dependent):

| Tier | Target class | Code+Static | Transaction context | Contact execution (kernel only) | Contactless execution (kernel only) |
|---|---|---|---|---|---|
| A | Cortex‑M / RTOS | ≤ 256 KB | ≤ 4 KB | ≤ 80 ms | ≤ 40 ms |
| B | Linux embedded | ≤ 1 MB | ≤ 32 KB | ≤ 60 ms | ≤ 30 ms |
| C | Android POS | not limited | not limited | performance‑bound (aim ≤ 50 ms) | performance‑bound (aim ≤ 25 ms) |

---

## 16. Testing and Certification Evidence

### 16.1 Testing Requirements

| Test level | Scope | Coverage target |
|---|---|---|
| Unit | Each function (TLV, APDU builder, TVR/TSI, state machine) | ≥95 % branch coverage |
| Integration | Full transaction with simulated card (APDU script replay) | 100 % of EMV test plan for each scheme |
| Fuzz | APDU parser, TLV parser, configuration parser | 1 million iterations, no crash/memory leak |
| Simulator | Run EMVCo test tool (e.g., Fime Eval4dev) | Pass all relevant test cases for target schemes |

### 16.2 Certification Evidence Artifacts

| Artifact | Description | Format | Required by |
|---|---|---|---|
| Conformance statement | Mapping of kernel functions to EMV requirements | Spreadsheet | Lab |
| Configuration manifest | AID list, CAPKs, TACs, IACs, limits per scheme | JSON + signature | Lab |
| Trace logs (masked) | Full APDU exchange for every test case | PCAP or structured JSON | Lab |
| Unit test report | Coverage, pass/fail, environment | HTML/XML | Internal |
| Static analysis report | MISRA C (or equivalent) compliance | Report | Lab (depending) |
| Fuzzing report | No crashes or memory leaks | Log | Internal |
| PCI PTS integration statement | How kernel separates PIN handling | Document | Lab, acquirer |
| Lab submission pack | All above + device under test + test harness | Archive | EMVCo laboratory |

> **KRN‑CERT‑003**: The kernel **SHALL** achieve EMVCo Level 2 certification for each claimed scheme and interface (contact, contactless, C‑8).  
> **KRN‑CERT‑004**: The kernel **SHOULD** pass a third‑party penetration test focused on APDU injection and state machine bypass.

---

## 17. Appendices

### Appendix A – Complete TLV Catalogue (CSV format)

**File:** `tlv_catalogue.csv` (available as a separate file)

### Appendix B – APDU Command Summary Table

| Command | CLA | INS | P1 | P2 | Data | Le | Response |
|---|---|---|---|---|---|---|---|
| SELECT (DF) | `00` | `A4` | `04` | `00` | AID | `00` | FCI |
| SELECT (PSE) | `00` | `A4` | `04` | `00` | `1PAY.SYS.DDF01` | `00` | FCI |
| SELECT (PPSE) | `00` | `A4` | `04` | `00` | `2PAY.SYS.DDF01` | `00` | FCI |
| GPO | `80` | `A8` | `00` | `00` | PDOL | `00` | `77` / `80` |
| READ RECORD | `00` | `B2` | rec | SFI\|`04` | – | `00` | Record |
| INTERNAL AUTH | `00` | `88` | `00` | `00` | DDOL | `00` | Signature |
| VERIFY (offline) | `00` | `20` | `00` | `00` | PIN block | – | `90 00` / `63 CX` |
| GENERATE AC (1st) | `80` | `AE` | type | `00` | CDOL1 | `00` | Cryptogram |
| GENERATE AC (2nd) | `80` | `AE` | `00` | `00` | CDOL2 | `00` | Cryptogram |
| EXTERNAL AUTH | `00` | `82` | `00` | `00` | ARPC | – | `90 00` |

### Appendix C – Test Vectors for ODA

**File:** `oda_test_vectors.json` (available as a separate file; each vector contains CAPK modulus and exponent, issuer public key certificate, ICC public key certificate, static signature data, DDOL input, INTERNAL AUTHENTICATE response, GENERATE AC response with CDA signature, expected recovered data, and expected TVR/TSI)

### Appendix D – Trace Log Format Specification (JSON)

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

(All PANs and track data masked; only last 4 digits of PAN shown.)

### Appendix E – Full State Machine Transition Table (CSV format)

**File:** `state_machine.csv` (available as a separate file; all CSV fields containing commas **SHALL** be double‑quoted)

### Appendix F – Scheme Profile Examples (Visa, Mastercard, C‑8)

**File:** `scheme_profiles.cert.json` (available as a separate file; contains **real, non‑placeholder** scheme, AID, CAPK, TAC/IAC, limit, and kernel parameters used for lab testing; dummy examples are clearly marked as non‑certification)

---

**End of Specification v4.0**