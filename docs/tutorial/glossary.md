# Glossary

This glossary defines EMV and Hyperion terms used throughout the tutorial
series, source code, tests, and certification evidence documents. It is written
for engineers who need practical vocabulary before reading EMV kernel code. It
is not a replacement for licensed EMVCo, payment scheme, acquirer, PCI PTS,
device, or laboratory documentation.

## AC

Application Cryptogram. A card-generated cryptographic result returned during
GENERATE AC processing. Common AC outcomes are ARQC, TC, and AAC.

## AAC

Application Authentication Cryptogram. A card-generated cryptogram that usually
indicates offline decline.

## ADF

Application Definition File. The card application selected by AID or directory
entry.

## AFL

Application File Locator. Data returned by GPO that tells the kernel which card
records to read and which records participate in offline authentication.

## AID

Application Identifier. Identifies a payment application or selectable
application on the card.

## AIP

Application Interchange Profile. Card-provided capability flags returned by
GPO. The kernel uses AIP to decide which processing steps are available, such as
offline data authentication and cardholder verification.

## APDU

Application Protocol Data Unit. The command and response envelope used between
terminal and card. APDU command fields include CLA, INS, P1, P2, Lc, command
data, and sometimes Le.

## Application Selection

The process of discovering and selecting the payment application to run. Contact
flows can use PSE or direct AID selection. Contactless flows commonly start with
PPSE and then select an application AID.

## ARC

Authorization Response Code. Host or issuer decision code returned after online
authorization, commonly stored in tag `8A`.

## ARPC

Authorization Response Cryptogram. Issuer authentication value returned through
the online host path where applicable.

## ARQC

Authorization Request Cryptogram. A card-generated cryptogram requesting online
authorization.

## ATC

Application Transaction Counter. Card-maintained transaction counter included
in cryptographic inputs and risk-management decisions.

## BER-TLV

Basic Encoding Rules Tag-Length-Value. The encoding form EMV uses for many
card and terminal data objects. Hyperion parser code treats malformed length,
tag, and constructed-value boundaries as security-sensitive inputs.

## BIN / IIN

Bank Identification Number or Issuer Identification Number. The leading digits
of a PAN that identify the issuing institution or network range.

## CAPK

Certification Authority Public Key. Public key material used in offline data
authentication. Production CAPKs require accepted provenance, expiry checks, and
integrity checks.

## Cardholder Data

Data that identifies or can identify the cardholder account, including PAN and
Track 2 equivalent data. It must be handled and logged under strict masking and
security policy.

## CDA

Combined Dynamic Data Authentication / Application Cryptogram generation. ODA
method that binds dynamic authentication to the GENERATE AC path.

## CDOL

Card Risk Management Data Object List. A DOL that defines data the terminal
must provide to GENERATE AC. CDOL1 is used for the first GENERATE AC and CDOL2
is commonly used for the second GENERATE AC after online authorization.

## CDCVM

Consumer Device Cardholder Verification Method. A contactless cardholder
verification result performed on a consumer device, subject to scheme and
profile rules.

## CID

Cryptogram Information Data. A byte returned with GENERATE AC response data
that identifies the card cryptogram type and preserves additional card result
flags.

## CLA

Class byte in an APDU command. CLA helps identify command class and secure
messaging context.

## Contact Interface

The chip-card path where terminal and ICC communicate through physical contacts.
Contact EMV flows are distinct from contactless flows, even when they share
data objects and high-level transaction stages.

## Contactless Interface

The proximity path where terminal and card or mobile device communicate over
the RF interface. Contactless kernels also depend on entry point behavior,
kernel mapping, reader limits, and scheme-specific outcome handling.

## CVM

Cardholder Verification Method. A rule or result describing how the cardholder
is verified, such as no CVM, signature, offline PIN, online PIN, or CDCVM.

## CVM List

Card-provided list of CVM rules and conditions. The kernel evaluates the list
against transaction amount, terminal capabilities, interface, and profile
policy.

## DDA

Dynamic Data Authentication. ODA method using INTERNAL AUTHENTICATE and signed
dynamic data.

## DDOL

Dynamic Data Authentication Data Object List. A DOL used to build data for
INTERNAL AUTHENTICATE during DDA.

## DDF

Directory Definition File. A card directory file, such as PPSE or PSE, used to
discover available applications.

## DF Name

Dedicated File name. In EMV application selection, the DF Name commonly carries
the AID that identifies an application.

## DOL

Data Object List. A list of tags and lengths that tells the terminal what data
to provide in a command. PDOL, CDOL, DDOL, and TDOL are specialized DOLs.

## EMV

The global payment card specifications and ecosystem originally named after
Europay, Mastercard, and Visa. In this repository, EMV generally refers to
contact and contactless chip transaction behavior.

## EMVCo

The standards body that maintains EMV specifications, test processes, and
approval frameworks. Hyperion documentation distinguishes repository evidence
from formal EMVCo or scheme approval artifacts.

## Entry Point

Contactless component that discovers candidates, selects the correct
contactless kernel, applies reader limits, and coordinates outcome presentation.
Hyperion tracks entry point responsibilities separately from core kernel logic.

## FCI

File Control Information. Template data returned by SELECT responses. It can
contain application labels, priority indicators, PDOL, and directory entries.

## Floor Limit

A terminal or profile threshold used during terminal risk management. A
transaction over the applicable floor limit may be forced online.

## GENERATE AC

Card command that requests an application cryptogram. The first GENERATE AC can
lead to ARQC, TC, or AAC. A second GENERATE AC may be used after online
authorization depending on interface, profile, and card behavior.

## GPO

Get Processing Options. Command used after application selection to request AIP
and AFL.

## Host Response

The authorization response returned from the issuer or host system after an
online request. Kernel-relevant data can include ARC, issuer authentication
data, issuer scripts, and final decision inputs.

## IAD

Issuer Application Data. Issuer-defined data, often carried in tag `9F10`.
Hyperion treats profile-defined issuer application data as sensitive for trace
policy.

## IAC

Issuer Action Code. Card or profile data used with TVR during terminal action
analysis.

## ICC

Integrated Circuit Card. The chip card or secure element participating in the
transaction.

## INS

Instruction byte in an APDU command. Examples include SELECT, READ RECORD, GET
PROCESSING OPTIONS, INTERNAL AUTHENTICATE, and GENERATE AC.

## Issuer Authentication

Kernel step that validates issuer authentication data, commonly using ARPC or
scheme-defined data in the online response path.

## Issuer Script

Issuer-provided APDU commands sent to the card after online authorization.
Scripts can run before or after final GENERATE AC depending on profile and
script phase.

## Kernel

The Level 2 EMV transaction engine. It implements EMV protocol decisions and
card interaction rules, but it is not the POS application, host, PED, Level 1
reader firmware, or certification authority.

## Kernel ID

Identifier used in contactless environments to select or describe the
contactless kernel behavior for a payment application or scheme profile.

## Lc

APDU command field that encodes the length of command data.

## Le

APDU command field that encodes the maximum response length expected by the
terminal.

## Level 1

Physical or RF interface layer for card communication. Level 1 evidence is
external to Hyperion's Level 2 kernel source.

## Level 2

EMV kernel layer. Hyperion-X-EMV targets this layer.

## Level 3

Payment application and terminal business workflow layer. Level 3 integrates
kernel outcomes with merchant UI, transaction routing, host messaging, receipt
logic, reversal handling, and acquirer rules.

## Merchant Category Code

Code identifying the merchant business category. Some terminal, issuer, or
scheme rules can use merchant category as part of authorization or risk policy.

## Offline Data Authentication

See ODA.

## Offline PIN

PIN verification performed between terminal/PED and card rather than by the
issuer host. Offline PIN handling must keep PIN material outside ordinary
application logs and memory surfaces.

## ODA

Offline Data Authentication. The family of SDA, DDA, and CDA checks.

## Online Authorization

The host path used when a card returns ARQC or when terminal policy requires an
online decision. The kernel prepares EMV data, while the Level 3 or host layer
normally formats and sends the authorization request.

## Online PIN

PIN verification performed by the issuer or host path. The kernel may record
that online PIN was selected or performed, but PIN-block construction and secure
PIN capture belong to PED and host integration boundaries.

## Outcome

The kernel or entry point result reported to the payment application. Outcomes
can include approval, decline, online request, try another interface, restart,
or profile-defined UI/status signals.

## P1 / P2

APDU parameter bytes. Their meaning depends on the instruction. For example,
SELECT uses P1/P2 to describe selection behavior and requested response format.

## PAN

Primary Account Number. Sensitive cardholder account number. Production traces
must mask it.

## PDOL

Processing Options Data Object List. Card-provided DOL used to build the GPO
command.

## PED

PIN Entry Device. The secure component that captures or handles PIN material.

## POS Application

The merchant-facing Level 3 application that drives transaction workflow,
amount entry, receipts, reversals, host routing, and user interaction around
the kernel.

## Profile

Accepted scheme, acquirer, and product configuration used by the kernel. A
profile can define AIDs, kernel mappings, TAC/IAC values, CVM policy,
contactless limits, CDA controls, CAPK metadata, and issuer script policy.

## PPSE

Proximity Payment System Environment. Contactless directory selected through
`2PAY.SYS.DDF01`.

## PSE

Payment System Environment. Contact directory selected through
`1PAY.SYS.DDF01`.

## READ RECORD

Card command used to read application records identified by AFL entries. Record
data can contain cardholder data, certificates, application data, CVM lists,
and other EMV objects.

## Reader

The terminal hardware and firmware that provide Level 1 card communication and
reader-specific controls. A reader is not the same thing as the Level 2 kernel,
even when both are packaged in one device.

## Relay Resistance

Contactless protection mechanism or check that helps detect relay attacks where
a transaction is extended beyond expected proximity timing.

## RFU

Reserved For Future Use. RFU bits or values should not be repurposed by the
kernel without accepted standards or profile authority.

## RID

Registered Application Provider Identifier. The leading five bytes of an AID,
identifying the payment network or application provider.

## SDA

Static Data Authentication. ODA method that validates signed static application
data.

## SFI

Short File Identifier. Identifier used with AFL and READ RECORD to select card
records.

## Script Identifier

Optional issuer script identifier carried in tag `9F18` inside Template 71 or
Template 72. It lets Level 3 correlate script command results with the issuer
host response without logging script command bytes.

## SW1/SW2

Status bytes returned by the card in an APDU response. `9000` is success, while
other values are interpreted according to command and transaction context.

## TAC

Terminal Action Code. Terminal or profile action code used with TVR and IAC
during terminal action analysis.

## TAA

Terminal Action Analysis. Decision stage that combines TVR with action codes
and profile policy to request approval, decline, or online authorization.

## TC

Transaction Certificate. A card-generated cryptogram that usually indicates
offline approval or final approval.

## TDOL

Transaction Certificate Data Object List. A DOL associated with transaction
certificate data in some EMV flows.

## Terminal Capabilities

Terminal data describing supported cardholder verification, security, and
transaction processing features. Terminal capability values affect CVM,
restrictions, and contactless behavior.

## Terminal Risk Management

Kernel stage that evaluates floor limits, random transaction selection,
velocity checks, and other terminal-side risk inputs.

## TLV

Tag-Length-Value encoding used by EMV data objects.

## Track 2 Equivalent Data

Chip data object that represents magnetic-stripe-like account data. It can
include PAN, expiry date, service code, and discretionary data, so Hyperion
trace policy treats it as sensitive cardholder data.

## TSI

Transaction Status Information. Bitmap describing which transaction processing
steps were performed.

## TTQ

Terminal Transaction Qualifiers. Contactless terminal capability and behavior
bitmap.

## TVR

Terminal Verification Results. Bitmap that records verification, restriction,
risk, authentication, and script-processing conditions.

## Unpredictable Number

Terminal-provided random value used in cryptographic flows. Certification
evidence must show that production entropy is supplied from an accepted source,
not from deterministic test fixtures.
