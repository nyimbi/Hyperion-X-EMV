# Transaction Flow Tutorial

This tutorial walks through a simplified EMV transaction and maps each phase to
kernel responsibilities. Real transactions vary by interface, scheme profile,
card product, amount, terminal capability, and online result.

## Phase 1: Transaction Setup

Before card interaction, the payment application starts a transaction and gives
the kernel terminal-owned inputs:

- Amount and currency.
- Country code.
- Transaction date and type.
- Terminal type.
- Terminal capabilities.
- Additional terminal capabilities.
- Contact or contactless interface selection.
- Contactless TTQ when applicable.
- Unpredictable number source.
- Supported profiles and AIDs.

The kernel clears transaction state at the start of each transaction. That is
important because TVR, TSI, CVM result, card data, trace state, and host
response state must not leak across transactions.

## Phase 2: Application Selection

The kernel selects the payment application. In contact flows this can involve
PSE (`1PAY.SYS.DDF01`) or direct AID selection. In contactless flows this
usually starts with PPSE (`2PAY.SYS.DDF01`).

The selection phase answers:

- Which card applications are present?
- Which terminal profiles can support those applications?
- Which candidate wins when priorities conflict?
- Is partial AID selection allowed?
- Which exact ADF name should be selected next?

Hyperion keeps candidate parsing and signed-profile matching separate so card
claims do not silently override configured terminal support.

## Phase 3: Get Processing Options

After selecting an application, the kernel builds a GPO command. The command is
based on the card's PDOL and the terminal data available in the kernel data
store.

The GPO response normally provides:

- AIP: application interchange profile.
- AFL: application file locator.

The AIP tells the kernel which authentication and processing capabilities the
card claims. The AFL tells the kernel which records to read and which records
participate in offline authentication.

## Phase 4: Read Records

The kernel reads records in AFL order. Records can contain application data
used later in the transaction:

- PAN and Track 2 equivalent data.
- Expiration and effective dates.
- Application usage control.
- CVM list.
- Issuer action codes.
- CDOL definitions.
- Offline authentication material.

Record ingestion is a trust-boundary point. Hyperion blocks card-originated
records from overwriting terminal-owned, host-owned, generated, or dynamic
authentication objects.

## Phase 5: Offline Data Authentication

Offline data authentication gives the terminal evidence about card data
authenticity. Depending on card support and profile rules, a transaction may use
SDA, DDA, CDA, or no ODA.

At a high level:

- SDA validates signed static application data.
- DDA uses INTERNAL AUTHENTICATE and signed dynamic data.
- CDA binds dynamic authentication to GENERATE AC behavior.

Repository fixtures can prove structure and implementation behavior, but final
certification needs lab-supplied cryptographic vectors and accepted CAPKs.

## Phase 6: Processing Restrictions

Processing restrictions compare card and terminal context:

- Application effective date.
- Application expiration date.
- Application version.
- Application usage control.
- Terminal country and transaction type.

Failures are represented in TVR bits. The kernel should not invent non-standard
bits or hide restriction failures in generic errors.

## Phase 7: Cardholder Verification

The CVM phase decides how the cardholder should be verified:

- No CVM.
- Signature.
- Online PIN.
- Offline plaintext PIN through PED-owned VERIFY.
- Offline enciphered PIN through PED-owned support.
- CDCVM for supported contactless profiles.

Hyperion keeps the clear PIN outside the kernel. Offline PIN paths use opaque
PED-owned handles and update CVM Results plus TVR according to VERIFY status.

## Phase 8: Terminal Risk Management

Terminal risk management decides whether terminal-side risk controls should
push the transaction online:

- Floor limit.
- Random transaction selection.
- Velocity checking.
- Merchant or exception conditions.

These decisions set TSI and TVR state that later participates in terminal
action analysis.

## Phase 9: Terminal Action Analysis

Terminal action analysis compares TVR against action codes:

- Issuer action codes from the card or profile fallback.
- Terminal action codes from the accepted profile.
- Terminal online capability.

The result decides whether the first GENERATE AC should request an AAC, TC, or
ARQC. The card still returns the actual cryptogram type. The kernel must parse
and respect the card response rather than assume the requested type succeeded.

## Phase 10: First GENERATE AC

The kernel builds CDOL1 data and sends GENERATE AC. The card may return:

- AAC: application authentication cryptogram, usually an offline decline.
- TC: transaction certificate, usually an offline approval.
- ARQC: authorization request cryptogram, requiring online authorization.

Hyperion does not generate ARQC, TC, or AAC cryptograms. The card generates
them. The kernel parses and routes them.

## Phase 11: Online Authorization

When the card returns ARQC, the kernel prepares an online authorization package
for the payment application or host layer. The package must include the EMV data
needed by the acquirer or issuer while preserving redaction policy in traces.

The host path is outside the kernel. The host may return an authorization
response code, issuer authentication data, and issuer scripts.

## Phase 12: Issuer Authentication And Scripts

If issuer authentication data is present, the kernel performs EXTERNAL
AUTHENTICATE or the scheme-defined equivalent path. Issuer scripts are then
processed in the correct phase and order.

The kernel records script results and sets phase-specific TVR bits. Critical
script failure can stop remaining commands. Non-critical failure can continue
while preserving evidence.

## Phase 13: Final GENERATE AC

If required, the kernel builds CDOL2 data and sends a final GENERATE AC. This
resolves the online path into a final card decision.

Some profiles and outcomes can skip final GENERATE AC. That must be explicit,
tested, and reflected in trace evidence.

## Phase 14: Outcome And Evidence

The kernel returns a final outcome and leaves evidence:

- Final state.
- TVR and TSI.
- CVM result.
- Issuer script results.
- Online handoff package, if any.
- Masked trace records.
- Profile and ABI identity metadata.

Certification depends on being able to map these outcomes back to requirements,
tests, traces, and external lab artifacts.

