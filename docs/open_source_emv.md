Yes, there are **open-source and source-available EMV kernel or EMV-kernel-adjacent projects**, but I would not treat any of the public open-source repositories I found as a drop-in, certification-ready EMV Level 2 kernel.

The practical answer is:

> **There are useful open-source EMV stacks, parsers, simulators, and partial kernels. There are very few credible open-source, certification-ready EMV L2 kernels, and I found no public open-source Rust kernel suitable to adopt wholesale for your Hyperion objective.**

## Notable projects

| Project                   | Language / stack                  | Scope                                                                                                                                                                                                                                                       | Suitability for Hyperion                                                                                                         |
| ------------------------- | --------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| **dcemv**                 | .NET / C# ecosystem               | Describes itself as an open-source EMV payments stack with contactless EMV kernels 1, 2, 3, a contact EMV kernel for EMV 4.3, QR support, terminal payment application, UI controls, JavaCard applet, Android HCE applet, and reader drivers. ([GitHub][1]) | Useful reference architecture and test/playground source. Not an obvious Rust foundation or guaranteed certification path.       |
| **greenboxal/emv-kernel** | Go                                | Describes itself as a full EMV kernel implementation in Go, intended to process ICC transactions, perform risk management, and request application cryptograms. ([GitHub][2])                                                                               | Interesting conceptually, but Go is not ideal for your L2 kernel core. Use as reading material only.                             |
| **MohamedHassanNasr/emv** | Java / Android-oriented           | Working implementation of contactless EMV kernel 2 and 3, but the author explicitly warns it is not production code and that many mandatory features are missing. ([GitHub][3])                                                                             | Useful educational reference. Not certifiable.                                                                                   |
| **mrautio/emvpt**         | Rust                              | “Minimum Viable Payment Terminal” supporting simple EMV transaction cases for chip and contactless/NFC, with a terminal simulator and library. ([GitHub][4])                                                                                                | Most relevant to your Rust direction as a learning/reference project, but it is intentionally minimal, not a complete L2 kernel. |
| **openemv/emv-utils**     | C / utilities                     | Partial implementation of EMVCo specifications for payment terminals, mainly for validation/debugging, with stated possibility of growing into kernels. ([GitHub][5])                                                                                       | Useful for tools, parsing ideas, and validation utilities. Not a full kernel.                                                    |
| **emerald79/libpay**      | C / Linux toolkit                 | Toolkit for Linux-based payment solutions, focused on EMV Contactless specifications and possibly extendable. ([GitHub][6])                                                                                                                                 | Useful reference for Linux payment tooling. Not a complete modern certifiable kernel.                                            |
| **Switstack Moka**        | Source-available commercial stack | Source-available, hardware-agnostic EMV Level 2 stack marketed as ready-to-certify, with testing and certification tooling. ([switstack.io][7])                                                                                                             | Commercial/source-available option worth evaluating if speed-to-certification matters. Not open source in the ordinary sense.    |

## What this means for your Rust build

For Hyperion, I would treat these projects as **reference material**, not as a codebase to fork blindly.

The most relevant route is:

1. Study **mrautio/emvpt** for Rust transaction modeling, APDU interaction, and simulator structure.
2. Study **openemv/emv-utils** and **libpay** for TLV, EMV utilities, and Linux payment patterns.
3. Study **dcemv** for full-stack transaction architecture, but do not copy its design wholesale.
4. Consider **Switstack Moka** only as a commercial benchmark or fallback if certification speed becomes more important than owning the full stack.
5. Build the Hyperion kernel as a clean-room Rust implementation governed by your `spec.md`, annex schemas, licensed EMVCo/scheme specs, and lab-provided test data.

## Why not just fork one?

A certifiable EMV L2 kernel requires exact behavior across:

* PSE/PPSE and AID selection.
* GPO and AFL traversal.
* TLV/DOL correctness.
* SDA/DDA/CDA.
* CVM and CVM condition-code processing.
* TAC/IAC terminal action analysis.
* GENERATE AC and CID handling.
* Issuer authentication and scripts.
* Contactless/C-8 outcome behavior.
* Scheme-specific variations.
* Lab test traceability.

Most open-source repositories either deliberately stop short of production completeness or lack evidence of EMVCo approval. For example, one contactless implementation explicitly states that it is not production code and has many mandatory features missing. ([GitHub][3])

## Recommended stance

Use open-source EMV projects for **accelerated learning and test tooling**, not as the certified kernel core.

For Hyperion, the best path remains:

> **Rust clean-room core + C ABI + signed profile system + lab/scheme data plugged in later + reference comparisons against open-source projects and approved EMV test tools.**

That gives you ownership, memory-safety, architectural clarity, and a defensible certification story.

[1]: https://github.com/vicente-da-silva/dcemv?utm_source=chatgpt.com "vicente-da-silva/dcemv: Open Source EMV Payments Stack"
[2]: https://github.com/greenboxal/emv-kernel?utm_source=chatgpt.com "Full EMV kernel implementation in Go"
[3]: https://github.com/MohamedHassanNasr/emv?utm_source=chatgpt.com "MohamedHassanNasr/emv: EMV Kernel for contactless in ..."
[4]: https://github.com/mrautio/emvpt?utm_source=chatgpt.com "mrautio/emvpt: Minimum Viable Payment Terminal"
[5]: https://github.com/openemv/emv-utils?utm_source=chatgpt.com "openemv/emv-utils: EMV libraries and tools"
[6]: https://github.com/emerald79/libpay?utm_source=chatgpt.com "emerald79/libpay"
[7]: https://www.switstack.io/moka?utm_source=chatgpt.com "Switstack Moka | Deploy and Own EMV L2 Across Any ..."
