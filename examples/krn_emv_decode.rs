use hyperion_emv::cid::{Cid, CryptogramType};
use hyperion_emv::config::decode_hex;
use hyperion_emv::cvm::{parse_cvm_list, CvmMethod};
use hyperion_emv::dol::parse_dol;
use hyperion_emv::state::{Tsi, Tvr};
use hyperion_emv::sw::{classify, ApduContext, StatusAction, StatusWord};
use hyperion_emv::tlv;
use std::fmt::Write;
use std::process;

fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    match run(&args[1..]) {
        Ok(out) => print!("{out}"),
        Err(err) => {
            eprintln!("{err}");
            eprintln!("{}", usage());
            process::exit(2);
        }
    }
}

fn run(args: &[String]) -> Result<String, String> {
    let Some(mode) = args.first().map(String::as_str) else {
        return Err("missing decode mode".to_string());
    };
    match mode {
        "tlv" => decode_tlv(arg_hex(args, 1, "tlv")?),
        "dol" => decode_dol(arg_hex(args, 1, "dol")?),
        "cvm-list" => decode_cvm_list(arg_hex(args, 1, "cvm-list")?),
        "tvr" => decode_tvr(arg_hex(args, 1, "tvr")?),
        "tsi" => decode_tsi(arg_hex(args, 1, "tsi")?),
        "cid" => decode_cid(arg_hex(args, 1, "cid")?),
        "sw" => {
            if args.len() != 3 {
                return Err("sw mode requires <context> <SW1SW2>".to_string());
            }
            let context = parse_context(&args[1])?;
            let sw = parse_status_word(&args[2])?;
            Ok(decode_status_word(context, sw))
        }
        "apdu" => decode_apdu(arg_hex(args, 1, "apdu")?),
        "help" | "--help" | "-h" => Ok(format!("{}\n", usage())),
        _ => Err(format!("unknown decode mode: {mode}")),
    }
}

fn usage() -> &'static str {
    "usage: krn_emv_decode <tlv|dol|cvm-list|tvr|tsi|cid|apdu> <hex>\n\
     usage: krn_emv_decode sw <context> <SW1SW2>\n\
     contexts: select-pse, select-aid, gpo, read-record, verify, generate-ac,\n\
     internal-authenticate, external-authenticate, issuer-script-critical,\n\
     issuer-script-noncritical"
}

fn arg_hex(args: &[String], idx: usize, mode: &str) -> Result<Vec<u8>, String> {
    if args.len() != idx + 1 {
        return Err(format!("{mode} mode requires one hex argument"));
    }
    decode_hex(&args[idx]).map_err(|err| format!("invalid hex for {mode}: {}", err.name()))
}

fn decode_tlv(bytes: Vec<u8>) -> Result<String, String> {
    let tlvs =
        tlv::parse_many(&bytes).map_err(|err| format!("TLV parse failed: {}", err.name()))?;
    let flat = tlv::flatten(&tlvs);
    let mut out = String::new();
    let _ = writeln!(out, "type=tlv");
    let _ = writeln!(out, "count={}", flat.len());
    for node in flat {
        let _ = writeln!(
            out,
            "tag={} constructed={} len={} value_policy=suppressed",
            hex_upper(node.tag),
            node.constructed,
            node.value.len()
        );
    }
    Ok(out)
}

fn decode_dol(bytes: Vec<u8>) -> Result<String, String> {
    let entries = parse_dol(&bytes).map_err(|err| format!("DOL parse failed: {}", err.name()))?;
    let mut out = String::new();
    let _ = writeln!(out, "type=dol");
    let _ = writeln!(out, "count={}", entries.len());
    for entry in entries {
        let _ = writeln!(out, "tag={} len={}", hex_upper(&entry.tag), entry.length);
    }
    Ok(out)
}

fn decode_cvm_list(bytes: Vec<u8>) -> Result<String, String> {
    let list =
        parse_cvm_list(&bytes).map_err(|err| format!("CVM list parse failed: {}", err.name()))?;
    let mut out = String::new();
    let _ = writeln!(out, "type=cvm-list");
    let _ = writeln!(out, "amount_x={}", list.amount_x);
    let _ = writeln!(out, "amount_y={}", list.amount_y);
    let _ = writeln!(out, "rule_count={}", list.rules.len());
    for (idx, rule) in list.rules.iter().enumerate() {
        let _ = writeln!(
            out,
            "rule={} method={} continue_on_failure={} condition=0x{:02X} offline_pin_required={} signature_required={}",
            idx,
            cvm_method_name(rule.method),
            rule.continue_on_failure(),
            rule.condition_code,
            rule.method.requires_offline_pin(),
            rule.method.requires_signature()
        );
    }
    Ok(out)
}

fn decode_cid(bytes: Vec<u8>) -> Result<String, String> {
    let [raw]: [u8; 1] = bytes
        .try_into()
        .map_err(|_| "CID must be exactly 1 byte".to_string())?;
    let cid = Cid::new(raw);
    let mut out = String::new();
    let _ = writeln!(out, "type=cid");
    let _ = writeln!(out, "raw=0x{:02X}", cid.raw());
    let _ = writeln!(
        out,
        "cryptogram_type={}",
        cryptogram_type_name(cid.cryptogram_type())
    );
    let _ = writeln!(out, "advice_required={}", cid.advice_required());
    let _ = writeln!(out, "reason_advice_code=0x{:02X}", cid.reason_advice_code());
    Ok(out)
}

fn decode_tvr(bytes: Vec<u8>) -> Result<String, String> {
    let raw: [u8; 5] = bytes
        .try_into()
        .map_err(|_| "TVR must be exactly 5 bytes".to_string())?;
    let mut out = String::new();
    let _ = writeln!(out, "type=tvr");
    let _ = writeln!(
        out,
        "rfu_bits={}",
        raw.iter()
            .zip(Tvr::ALLOWED_MASKS)
            .any(|(byte, allowed)| byte & !allowed != 0)
    );
    append_set_bits(&mut out, &raw, &TVR_BITS);
    Ok(out)
}

fn decode_tsi(bytes: Vec<u8>) -> Result<String, String> {
    let raw: [u8; 2] = bytes
        .try_into()
        .map_err(|_| "TSI must be exactly 2 bytes".to_string())?;
    let mut out = String::new();
    let _ = writeln!(out, "type=tsi");
    let _ = writeln!(
        out,
        "rfu_bits={}",
        raw.iter()
            .zip(Tsi::ALLOWED_MASKS)
            .any(|(byte, allowed)| byte & !allowed != 0)
    );
    append_set_bits(&mut out, &raw, &TSI_BITS);
    Ok(out)
}

fn append_set_bits(out: &mut String, raw: &[u8], bits: &[BitName]) {
    let mut count = 0usize;
    for bit in bits {
        if raw
            .get(bit.position.0)
            .is_some_and(|byte| byte & bit.position.1 != 0)
        {
            let _ = writeln!(out, "bit={}", bit.name);
            count += 1;
        }
    }
    if count == 0 {
        let _ = writeln!(out, "bit_count=0");
    }
}

fn decode_status_word(context: ApduContext, sw: StatusWord) -> String {
    let mut out = String::new();
    let action = classify(context, sw);
    let _ = writeln!(out, "type=status-word");
    let _ = writeln!(out, "context={}", context_name(context));
    let _ = writeln!(out, "sw={:02X}{:02X}", sw.sw1, sw.sw2);
    let _ = writeln!(out, "action={}", action_name(action));
    out
}

fn decode_apdu(bytes: Vec<u8>) -> Result<String, String> {
    let apdu = ShortCommandApdu::parse(&bytes).map_err(|err| err.to_string())?;
    let mut out = String::new();
    let _ = writeln!(out, "type=apdu");
    let _ = writeln!(out, "cla={:02X}", apdu.cla);
    let _ = writeln!(out, "ins={:02X}", apdu.ins);
    let _ = writeln!(out, "p1={:02X}", apdu.p1);
    let _ = writeln!(out, "p2={:02X}", apdu.p2);
    let _ = writeln!(out, "lc={}", apdu.lc.unwrap_or(0));
    let _ = writeln!(
        out,
        "le={}",
        apdu.le
            .map(|le| le.to_string())
            .unwrap_or_else(|| "absent".to_string())
    );
    let _ = writeln!(out, "data_policy=suppressed");
    Ok(out)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ShortCommandApdu {
    cla: u8,
    ins: u8,
    p1: u8,
    p2: u8,
    lc: Option<usize>,
    le: Option<u8>,
}

impl ShortCommandApdu {
    fn parse(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 4 {
            return Err("APDU command must include CLA INS P1 P2");
        }
        let mut apdu = Self {
            cla: bytes[0],
            ins: bytes[1],
            p1: bytes[2],
            p2: bytes[3],
            lc: None,
            le: None,
        };
        match bytes.len() {
            4 => Ok(apdu),
            5 => {
                apdu.le = Some(bytes[4]);
                Ok(apdu)
            }
            _ => {
                if bytes[4] == 0 {
                    return Err("extended-length APDUs are not decoded by this pre-lab utility");
                }
                let lc = bytes[4] as usize;
                let data_end = 5usize.checked_add(lc).ok_or("APDU length overflow")?;
                if data_end > bytes.len() {
                    return Err("APDU Lc exceeds command length");
                }
                apdu.lc = Some(lc);
                match bytes.len() - data_end {
                    0 => Ok(apdu),
                    1 => {
                        apdu.le = Some(bytes[data_end]);
                        Ok(apdu)
                    }
                    _ => Err("APDU command has trailing bytes after Lc/data/Le"),
                }
            }
        }
    }
}

fn parse_status_word(input: &str) -> Result<StatusWord, String> {
    let bytes = decode_hex(input).map_err(|err| format!("invalid status word: {}", err.name()))?;
    match bytes.as_slice() {
        [sw1, sw2] => Ok(StatusWord::new(*sw1, *sw2)),
        _ => Err("status word must be exactly two bytes".to_string()),
    }
}

fn parse_context(input: &str) -> Result<ApduContext, String> {
    match input {
        "select-pse" => Ok(ApduContext::SelectPse),
        "select-aid" => Ok(ApduContext::SelectAid),
        "gpo" => Ok(ApduContext::Gpo),
        "read-record" => Ok(ApduContext::ReadRecord),
        "verify" => Ok(ApduContext::Verify),
        "generate-ac" => Ok(ApduContext::GenerateAc),
        "internal-authenticate" => Ok(ApduContext::InternalAuthenticate),
        "external-authenticate" => Ok(ApduContext::ExternalAuthenticate),
        "issuer-script-critical" => Ok(ApduContext::IssuerScript { critical: true }),
        "issuer-script-noncritical" => Ok(ApduContext::IssuerScript { critical: false }),
        _ => Err(format!("unknown APDU context: {input}")),
    }
}

fn context_name(context: ApduContext) -> &'static str {
    match context {
        ApduContext::SelectPse => "select-pse",
        ApduContext::SelectAid => "select-aid",
        ApduContext::Gpo => "gpo",
        ApduContext::ReadRecord => "read-record",
        ApduContext::Verify => "verify",
        ApduContext::GenerateAc => "generate-ac",
        ApduContext::InternalAuthenticate => "internal-authenticate",
        ApduContext::ExternalAuthenticate => "external-authenticate",
        ApduContext::IssuerScript { critical: true } => "issuer-script-critical",
        ApduContext::IssuerScript { critical: false } => "issuer-script-noncritical",
    }
}

fn action_name(action: StatusAction) -> String {
    match action {
        StatusAction::Success => "success".to_string(),
        StatusAction::GetResponse { length } => format!("get-response length={length}"),
        StatusAction::RetryWithLe { length } => format!("retry-with-le length={length}"),
        StatusAction::FallbackToDirectAid => "fallback-to-direct-aid".to_string(),
        StatusAction::TryNextAid => "try-next-aid".to_string(),
        StatusAction::EndOfRecords => "end-of-records".to_string(),
        StatusAction::ContinueWithTvr { bit } => {
            format!("continue-with-tvr bit={}", bit_name(bit))
        }
        StatusAction::PinFailed { tries_remaining } => {
            format!("pin-failed tries_remaining={tries_remaining}")
        }
        StatusAction::ContinueAfterScriptWarning => "continue-after-script-warning".to_string(),
        StatusAction::ContinueAfterNonCriticalScriptFailure => {
            "continue-after-noncritical-script-failure".to_string()
        }
        StatusAction::Fail { error } => format!("fail error={}", error.name()),
    }
}

fn cvm_method_name(method: CvmMethod) -> String {
    match method {
        CvmMethod::OfflinePlaintextPin => "offline-plaintext-pin".to_string(),
        CvmMethod::OnlinePin => "online-pin".to_string(),
        CvmMethod::OfflinePlaintextPinAndSignature => {
            "offline-plaintext-pin-and-signature".to_string()
        }
        CvmMethod::OfflineEncipheredPin => "offline-enciphered-pin".to_string(),
        CvmMethod::OfflineEncipheredPinAndSignature => {
            "offline-enciphered-pin-and-signature".to_string()
        }
        CvmMethod::Signature => "signature".to_string(),
        CvmMethod::FailCvmProcessing => "fail-cvm-processing".to_string(),
        CvmMethod::NoCvmRequired => "no-cvm-required".to_string(),
        CvmMethod::SchemeSpecific(code) => format!("scheme-specific-0x{code:02X}"),
        CvmMethod::Unknown(code) => format!("unknown-0x{code:02X}"),
    }
}

fn cryptogram_type_name(cryptogram_type: CryptogramType) -> &'static str {
    match cryptogram_type {
        CryptogramType::Aac => "aac",
        CryptogramType::Tc => "tc",
        CryptogramType::Arqc => "arqc",
        CryptogramType::ApplicationAuthenticationReferral => "application-authentication-referral",
    }
}

fn bit_name(bit: (usize, u8)) -> &'static str {
    TVR_BITS
        .iter()
        .find(|entry| entry.position == bit)
        .map(|entry| entry.name)
        .unwrap_or("unknown")
}

fn hex_upper(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02X}");
    }
    out
}

#[derive(Clone, Copy)]
struct BitName {
    position: (usize, u8),
    name: &'static str,
}

const TVR_BITS: [BitName; 25] = [
    BitName {
        position: Tvr::B1_OFFLINE_DATA_AUTH_NOT_PERFORMED,
        name: "offline-data-authentication-not-performed",
    },
    BitName {
        position: Tvr::B1_SDA_FAILED,
        name: "sda-failed",
    },
    BitName {
        position: Tvr::B1_ICC_DATA_MISSING,
        name: "icc-data-missing",
    },
    BitName {
        position: Tvr::B1_CARD_ON_EXCEPTION_FILE,
        name: "card-on-exception-file",
    },
    BitName {
        position: Tvr::B1_DDA_FAILED,
        name: "dda-failed",
    },
    BitName {
        position: Tvr::B1_CDA_FAILED,
        name: "cda-failed",
    },
    BitName {
        position: Tvr::B2_DIFFERENT_APPLICATION_VERSIONS,
        name: "different-application-versions",
    },
    BitName {
        position: Tvr::B2_EXPIRED_APPLICATION,
        name: "expired-application",
    },
    BitName {
        position: Tvr::B2_APPLICATION_NOT_YET_EFFECTIVE,
        name: "application-not-yet-effective",
    },
    BitName {
        position: Tvr::B2_REQUESTED_SERVICE_NOT_ALLOWED,
        name: "requested-service-not-allowed",
    },
    BitName {
        position: Tvr::B2_NEW_CARD,
        name: "new-card",
    },
    BitName {
        position: Tvr::B3_CARDHOLDER_VERIFICATION_NOT_SUCCESSFUL,
        name: "cardholder-verification-not-successful",
    },
    BitName {
        position: Tvr::B3_UNRECOGNIZED_CVM,
        name: "unrecognized-cvm",
    },
    BitName {
        position: Tvr::B3_PIN_TRY_LIMIT_EXCEEDED,
        name: "pin-try-limit-exceeded",
    },
    BitName {
        position: Tvr::B3_PIN_PAD_NOT_PRESENT_OR_NOT_WORKING,
        name: "pin-pad-not-present-or-not-working",
    },
    BitName {
        position: Tvr::B3_PIN_NOT_ENTERED,
        name: "pin-not-entered",
    },
    BitName {
        position: Tvr::B3_ONLINE_PIN_ENTERED,
        name: "online-pin-entered",
    },
    BitName {
        position: Tvr::B4_FLOOR_LIMIT_EXCEEDED,
        name: "floor-limit-exceeded",
    },
    BitName {
        position: Tvr::B4_LOWER_CONSECUTIVE_OFFLINE_LIMIT_EXCEEDED,
        name: "lower-consecutive-offline-limit-exceeded",
    },
    BitName {
        position: Tvr::B4_UPPER_CONSECUTIVE_OFFLINE_LIMIT_EXCEEDED,
        name: "upper-consecutive-offline-limit-exceeded",
    },
    BitName {
        position: Tvr::B4_RANDOM_TRANSACTION_SELECTION_PERFORMED,
        name: "random-transaction-selection-performed",
    },
    BitName {
        position: Tvr::B4_MERCHANT_FORCED_TRANSACTION_ONLINE,
        name: "merchant-forced-transaction-online",
    },
    BitName {
        position: Tvr::B5_ISSUER_AUTHENTICATION_FAILED,
        name: "issuer-authentication-failed",
    },
    BitName {
        position: Tvr::B5_SCRIPT_PROCESSING_FAILED_BEFORE_FINAL_GAC,
        name: "script-processing-failed-before-final-gac",
    },
    BitName {
        position: Tvr::B5_SCRIPT_PROCESSING_FAILED_AFTER_FINAL_GAC,
        name: "script-processing-failed-after-final-gac",
    },
];

const TSI_BITS: [BitName; 6] = [
    BitName {
        position: Tsi::OFFLINE_DATA_AUTHENTICATION_PERFORMED,
        name: "offline-data-authentication-performed",
    },
    BitName {
        position: Tsi::CARDHOLDER_VERIFICATION_PERFORMED,
        name: "cardholder-verification-performed",
    },
    BitName {
        position: Tsi::CARD_RISK_MANAGEMENT_PERFORMED,
        name: "card-risk-management-performed",
    },
    BitName {
        position: Tsi::ISSUER_AUTHENTICATION_PERFORMED,
        name: "issuer-authentication-performed",
    },
    BitName {
        position: Tsi::TERMINAL_RISK_MANAGEMENT_PERFORMED,
        name: "terminal-risk-management-performed",
    },
    BitName {
        position: Tsi::SCRIPT_PROCESSING_PERFORMED,
        name: "script-processing-performed",
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    fn string_arg(value: &str) -> String {
        value.to_string()
    }

    #[test]
    fn tlv_output_suppresses_values() {
        let out = decode_tlv(decode_hex("700A5A08123456789012345F").unwrap()).unwrap();

        assert!(out.contains("tag=70 constructed=true len=10"));
        assert!(out.contains("tag=5A constructed=false len=8"));
        assert!(out.contains("value_policy=suppressed"));
        assert!(!out.contains("123456789012345F"));
    }

    #[test]
    fn dol_output_lists_tags_and_lengths() {
        let out = decode_dol(decode_hex("9F66049F02069A03").unwrap()).unwrap();

        assert!(out.contains("type=dol"));
        assert!(out.contains("tag=9F66 len=4"));
        assert!(out.contains("tag=9F02 len=6"));
        assert!(out.contains("tag=9A len=3"));
    }

    #[test]
    fn cvm_list_output_names_rules_without_handles() {
        let out = decode_cvm_list(decode_hex("00000000000003E8430302031F03").unwrap()).unwrap();

        assert!(out.contains("type=cvm-list"));
        assert!(out.contains("amount_y=1000"));
        assert!(out.contains("rule=0 method=offline-plaintext-pin-and-signature"));
        assert!(out.contains("continue_on_failure=true"));
        assert!(out.contains("offline_pin_required=true signature_required=true"));
        assert!(out.contains("rule=1 method=online-pin"));
        assert!(out.contains("offline_pin_required=false signature_required=false"));
        assert!(out.contains("rule=2 method=no-cvm-required"));
        assert!(!out.contains("ped_handle"));
        assert!(!out.contains("feed"));
        assert!(!out.contains("beef"));
    }

    #[test]
    fn bitmap_output_names_tvr_and_tsi_bits() {
        let tvr = decode_tvr(decode_hex("8000040040").unwrap()).unwrap();
        let tsi = decode_tsi(decode_hex("5000").unwrap()).unwrap();

        assert!(tvr.contains("bit=offline-data-authentication-not-performed"));
        assert!(tvr.contains("bit=online-pin-entered"));
        assert!(tvr.contains("bit=issuer-authentication-failed"));
        assert!(tsi.contains("bit=cardholder-verification-performed"));
        assert!(tsi.contains("bit=issuer-authentication-performed"));
    }

    #[test]
    fn cid_output_masks_type_bits_and_preserves_advice_fields() {
        let out = decode_cid(decode_hex("8F").unwrap()).unwrap();

        assert!(out.contains("type=cid"));
        assert!(out.contains("raw=0x8F"));
        assert!(out.contains("cryptogram_type=arqc"));
        assert!(out.contains("advice_required=true"));
        assert!(out.contains("reason_advice_code=0x07"));
        assert!(!out.contains("cryptogram_type=application-authentication-referral"));
    }

    #[test]
    fn sw_output_is_context_specific() {
        let select = decode_status_word(ApduContext::SelectPse, StatusWord::new(0x6A, 0x82));
        let gpo = decode_status_word(ApduContext::Gpo, StatusWord::new(0x6A, 0x82));

        assert!(select.contains("action=fallback-to-direct-aid"));
        assert!(gpo.contains("action=fail error=KRN_ERR_MISSING_MANDATORY_TAG"));
    }

    #[test]
    fn apdu_output_suppresses_command_data() {
        let out = decode_apdu(decode_hex("80AE80000301020300").unwrap()).unwrap();

        assert!(out.contains("cla=80"));
        assert!(out.contains("ins=AE"));
        assert!(out.contains("lc=3"));
        assert!(out.contains("le=0"));
        assert!(out.contains("data_policy=suppressed"));
        assert!(!out.contains("010203"));
    }

    #[test]
    fn malformed_apdu_is_rejected() {
        assert_eq!(
            ShortCommandApdu::parse(&[0x80, 0xAE, 0x80]).unwrap_err(),
            "APDU command must include CLA INS P1 P2"
        );
        assert_eq!(
            ShortCommandApdu::parse(&[0x80, 0xAE, 0x80, 0x00, 0x04, 0x01]).unwrap_err(),
            "APDU Lc exceeds command length"
        );
    }

    #[test]
    fn cli_routes_sw_mode() {
        let out = run(&[string_arg("sw"), string_arg("verify"), string_arg("63C2")]).unwrap();

        assert!(out.contains("context=verify"));
        assert!(out.contains("action=pin-failed tries_remaining=2"));
    }

    #[test]
    fn cli_routes_cid_mode() {
        let out = run(&[string_arg("cid"), string_arg("47")]).unwrap();

        assert!(out.contains("type=cid"));
        assert!(out.contains("cryptogram_type=tc"));
    }

    #[test]
    fn cli_rejects_unknown_mode() {
        assert!(run(&[string_arg("raw"), string_arg("9000")])
            .unwrap_err()
            .contains("unknown decode mode"));
    }

    #[test]
    fn parse_error_names_remain_stable() {
        assert_eq!(
            hyperion_emv::error::KernelError::ParseError.name(),
            "KRN_ERR_PARSE_ERROR"
        );
    }
}
