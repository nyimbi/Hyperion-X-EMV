# Where The Kernel Fits In The Payment Stack

This tutorial explains the layers around an EMV kernel and the contracts between
them.

## Stack Overview

The payment stack is easier to reason about if each layer has a narrow job:

```text
Card / Mobile Wallet
        |
Level 1 interface
        |
Level 2 EMV kernel
        |
Level 3 payment application
        |
Acquirer / processor / issuer network
```

The kernel is the Level 2 box. It does not replace the other boxes.

## Card Or Wallet

The card or wallet stores payment application data and responds to APDU
commands. The card may provide:

- Application identifiers and labels.
- Processing options.
- Application file locator records.
- PAN or Track 2 equivalent data.
- Application usage control.
- CVM list.
- Issuer action codes.
- Application cryptograms and dynamic authentication data.

The kernel must treat card-originated data carefully. Some card data is
informational. Some card data drives decisions. Some card data is sensitive.
Some tag values must not be allowed to overwrite terminal-owned values.

## Level 1

Level 1 is the electrical, contact, or contactless communication layer. It
handles the physical transport:

- Contact card reset and byte transport.
- Contactless polling, anticollision, and RF exchange.
- Low-level timing and device communication.

The Level 2 kernel should not implement device-specific RF drivers or contact
reader drivers. It should receive APDU responses and return APDU commands
through integration callbacks or adapter code.

## Level 2

Level 2 is the EMV kernel. Its job is to implement EMV transaction behavior:

- Selection.
- GPO.
- READ RECORD.
- Offline data authentication scaffolding and validation.
- Processing restrictions.
- CVM selection and result handling.
- Terminal risk management.
- Terminal action analysis.
- GENERATE AC.
- Online handoff.
- Issuer authentication.
- Issuer script processing.
- Contactless outcome handling.

Hyperion-X-EMV is this layer.

## Level 3

Level 3 is the payment application and terminal business workflow. It usually
owns:

- UI prompts.
- Receipt text.
- Merchant configuration.
- Transaction start and cancel policy.
- Online authorization message format.
- Host routing.
- Reconciliation and settlement.
- Device management.
- Acquirer and merchant-specific policy.

The kernel can produce an online authorization package, but the Level 3
application normally owns host messaging and final business workflow.

## PED And PCI PTS Boundary

PIN handling belongs in a certified secure PIN subsystem or PED. A kernel may
request offline PIN verification or consume an opaque PIN-handle result, but it
should not take custody of clear PIN bytes.

Hyperion models offline PIN through PED-owned opaque handles. That means:

- The kernel can reason about CVM flow.
- The PED owns sensitive PIN capture and PIN block handling.
- Logs and debug output must not expose PIN material.
- PCI PTS evidence remains outside repository-only closure.

## Scheme And Acquirer Profiles

The kernel should not guess scheme behavior from public examples. It needs
accepted profiles that define:

- Supported AIDs and interfaces.
- Kernel type.
- TAC/IAC and fallback behavior.
- CAPK metadata and checksums.
- CVM and CDCVM policy.
- Contactless limits.
- CDA controls.
- Issuer script criticality policy.

Hyperion rejects example-only profiles for certification and production modes.
Signed profiles and accepted CAPK bundles are certification inputs, not
repository-owned facts.

## Host And Issuer Boundary

When the kernel goes online, it prepares EMV data for the payment application or
host layer. The host or issuer may return:

- Authorization response code.
- Issuer authentication data.
- Issuer scripts.
- Authorization code.

The kernel can validate shape, update transaction state, process issuer
authentication, and sequence issuer scripts. It does not decide issuer risk
policy or own issuer cryptographic keys.

## Certification Boundary

Certification evidence crosses every layer:

- Level 1/device evidence proves the reader and terminal platform.
- Level 2 evidence proves kernel behavior.
- Level 3/acquirer evidence proves the payment application and host path.
- PCI PTS evidence proves the secure PIN and device security boundary.
- Scheme and lab evidence prove accepted behavior for the claimed scope.

Hyperion can provide a strong Level 2 baseline and repository-controlled
evidence. Final certification still requires external artifacts.

