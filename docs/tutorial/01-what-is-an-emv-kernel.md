# What Is An EMV Kernel?

An EMV kernel is the Level 2 transaction engine that interprets EMV card data,
drives the card interaction, applies terminal and scheme rules, and produces a
transaction outcome for the payment application.

It is not an operating-system kernel. It is not the POS application. It is not
the acquirer host. It is not the secure PIN entry device. It is the protocol
and decision component that sits between the card interface and the higher
payment application.

## The Short Version

During an EMV transaction, the kernel:

- Selects an application on the card.
- Builds and sends APDU commands.
- Parses TLV responses from the card.
- Tracks transaction state.
- Applies processing restrictions.
- Evaluates cardholder verification methods.
- Performs terminal risk management.
- Performs terminal action analysis.
- Requests one or more card cryptograms.
- Packages data for online authorization when required.
- Handles issuer authentication and issuer scripts after host response.
- Produces an outcome such as approve offline, decline offline, go online,
  try another interface, or complete after issuer processing.

## Why EMV Needs A Kernel

EMV transactions are structured around card, terminal, scheme, acquirer, and
issuer responsibilities. A payment application could try to implement every
rule directly, but that usually creates inconsistent behavior across terminal
models, schemes, interfaces, and integrations.

The kernel gives the terminal a single controlled place for EMV Level 2 logic.
That matters because EMV behavior is highly stateful:

- Card records are read in AFL order.
- Certain card data may not overwrite terminal-owned data.
- TVR and TSI bits must be set precisely.
- CVM choices depend on terminal capability, amount, transaction type, and card
  rules.
- Terminal action analysis depends on TAC, IAC, TVR, online capability, and
  profile data.
- Contactless flows may produce alternate-interface or CDCVM outcomes before
  a contact-like transaction completes.
- Issuer authentication and issuer scripts occur after online authorization and
  must not be confused with pre-online card data.

## Level 2 Responsibilities

In a typical EMV model:

- Level 1 handles the physical or RF interface.
- Level 2 handles the EMV protocol and kernel decisions.
- Level 3 handles the payment application, host messaging, receipts, UI,
  settlement, and terminal management.

The kernel is Level 2. It should own EMV invariant behavior, but it should not
own every part of a payment product.

## What A Kernel Should Not Own

A certification-ready kernel should avoid broad custody. Hyperion treats these
as outside the kernel core:

- Issuer master keys.
- Clear PIN values.
- PAN display policy and receipt formatting.
- Host authorization approval policy.
- Acquirer routing.
- Scheme profile authority.
- CAPK authority.
- Device and PCI PTS certification.
- Final lab approval.

The kernel may carry, mask, validate, or route data needed for these tasks, but
the owning system or certified device remains responsible for them.

## Common Inputs

An EMV kernel commonly receives:

- Terminal capabilities.
- Additional terminal capabilities.
- Terminal transaction qualifiers for contactless flows.
- Amount, currency, country, transaction date, transaction type, and
  unpredictable number.
- Supported AIDs and scheme profile configuration.
- TAC/IAC values and contactless limits.
- CAPK metadata and accepted public keys.
- Runtime callbacks for card I/O, random data, time, and online handoff.

## Common Outputs

The kernel commonly emits:

- APDU commands to send to the card.
- Parsed transaction state.
- TVR and TSI values.
- CVM result.
- Online authorization package.
- Issuer authentication and script processing results.
- Masked traces for support and lab review.
- A final outcome for the payment application.

## The Main Mental Model

Think of the kernel as a deterministic protocol engine with strict boundaries.
It should be easy to answer:

- Who owns this data?
- Is this value from the card, terminal, host, profile, or lab?
- Is this value sensitive?
- Which rule set allows this decision?
- Which test proves it?
- Which external artifact is still required?

Hyperion is organized around those questions.

