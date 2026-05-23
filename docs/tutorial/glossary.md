# Glossary

This glossary defines terms used throughout the Hyperion tutorials and source
documentation.

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
GPO.

## APDU

Application Protocol Data Unit. The command and response envelope used between
terminal and card.

## ARPC

Authorization Response Cryptogram. Issuer authentication value returned through
the online host path where applicable.

## ARQC

Authorization Request Cryptogram. A card-generated cryptogram requesting online
authorization.

## CAPK

Certification Authority Public Key. Public key material used in offline data
authentication. Production CAPKs require accepted provenance and integrity
checks.

## Cardholder Data

Data that identifies or can identify the cardholder account, including PAN and
Track 2 equivalent data. It must be handled and logged under strict masking and
security policy.

## CDA

Combined Dynamic Data Authentication / Application Cryptogram generation. ODA
method that binds dynamic authentication to the GENERATE AC path.

## CDOL

Card Risk Management Data Object List. A DOL that defines data the terminal
must provide to GENERATE AC.

## CDCVM

Consumer Device Cardholder Verification Method. A contactless cardholder
verification result performed on a consumer device, subject to scheme and
profile rules.

## CID

Cryptogram Information Data. A byte returned with GENERATE AC response data
that identifies the card cryptogram type and preserves additional card result
flags.

## CVM

Cardholder Verification Method. A rule or result describing how the cardholder
is verified.

## DDA

Dynamic Data Authentication. ODA method using INTERNAL AUTHENTICATE and signed
dynamic data.

## DDOL

Dynamic Data Authentication Data Object List. A DOL used to build data for
INTERNAL AUTHENTICATE during DDA.

## DOL

Data Object List. A list of tags and lengths that tells the terminal what data
to provide in a command.

## EMV

The global payment card specifications and ecosystem originally named after
Europay, Mastercard, and Visa. In this repository, EMV generally refers to
contact and contactless chip transaction behavior.

## FCI

File Control Information. Template data returned by SELECT responses. It can
contain application labels, priority indicators, PDOL, and directory entries.

## Floor Limit

A terminal or profile threshold used during terminal risk management. A
transaction over the applicable floor limit may be forced online.

## GPO

Get Processing Options. Command used after application selection to request AIP
and AFL.

## IAD

Issuer Application Data. Issuer-defined data, often carried in tag `9F10`.
Hyperion treats profile-defined issuer application data as sensitive for trace
policy.

## ICC

Integrated Circuit Card. The chip card or secure element participating in the
transaction.

## IAC

Issuer Action Code. Card or profile data used with TVR during terminal action
analysis.

## Issuer Script

Issuer-provided APDU commands sent to the card after online authorization.

## Kernel

The Level 2 EMV transaction engine. It implements EMV protocol decisions and
card interaction rules, but it is not the POS application, host, PED, or
certification authority.

## Level 1

Physical or RF interface layer for card communication.

## Level 2

EMV kernel layer. Hyperion-X-EMV targets this layer.

## Level 3

Payment application and terminal business workflow layer.

## ODA

Offline Data Authentication. The family of SDA, DDA, and CDA checks.

## Online Authorization

The host path used when a card returns ARQC or when terminal policy requires an
online decision. The kernel prepares EMV data, while the Level 3 or host layer
normally formats and sends the authorization request.

## PAN

Primary Account Number. Sensitive cardholder account number. Production traces
must mask it.

## PDOL

Processing Options Data Object List. Card-provided DOL used to build the GPO
command.

## PED

PIN Entry Device. The secure component that captures or handles PIN material.

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

## RFU

Reserved For Future Use. RFU bits or values should not be repurposed by the
kernel without accepted standards or profile authority.

## SDA

Static Data Authentication. ODA method that validates signed static
application data.

## SW1/SW2

Status bytes returned by the card in an APDU response. `9000` is success, while
other values are interpreted according to command and transaction context.

## TAC

Terminal Action Code. Terminal or profile action code used with TVR and IAC
during terminal action analysis.

## TC

Transaction Certificate. A card-generated cryptogram that usually indicates
offline approval or final approval.

## TDOL

Transaction Certificate Data Object List. A DOL associated with transaction
certificate data in some EMV flows.

## TLV

Tag-Length-Value encoding used by EMV data objects.

## TSI

Transaction Status Information. Bitmap describing which transaction processing
steps were performed.

## TTQ

Terminal Transaction Qualifiers. Contactless terminal capability and behavior
bitmap.

## TVR

Terminal Verification Results. Bitmap that records verification, restriction,
risk, authentication, and script-processing conditions.
