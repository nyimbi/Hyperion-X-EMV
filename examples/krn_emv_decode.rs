use hyperion_emv::cid::{Cid, CryptogramType};
use hyperion_emv::config::decode_hex;
use hyperion_emv::cvm::{parse_cvm_list, CvmMethod};
use hyperion_emv::dol::parse_dol;
use hyperion_emv::gac::parse_generate_ac_response;
use hyperion_emv::state::{Tsi, Tvr};
use hyperion_emv::sw::{classify, ApduContext, StatusAction, StatusWord};
use hyperion_emv::tlv;
use hyperion_emv::trace::{mask_apdu_response, ApduTraceContext, LogPolicy, MaskedValue};
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
        "gac" | "generate-ac-response" => decode_gac_response(arg_hex(args, 1, "gac")?),
        "termcap" | "terminal-capabilities" => {
            decode_terminal_capabilities(arg_hex(args, 1, "termcap")?)
        }
        "ttq" => decode_profile_defined_bitmap("ttq", arg_hex(args, 1, "ttq")?, 4),
        "ctq" => decode_profile_defined_bitmap("ctq", arg_hex(args, 1, "ctq")?, 1),
        "sw" => {
            if args.len() != 3 {
                return Err("sw mode requires <context> <SW1SW2>".to_string());
            }
            let context = parse_context(&args[1])?;
            let sw = parse_status_word(&args[2])?;
            Ok(decode_status_word(context, sw))
        }
        "apdu" => decode_apdu(arg_hex(args, 1, "apdu")?),
        "rapdu" | "response-apdu" => {
            if args.len() != 3 {
                return Err("response-apdu mode requires <context> <response-hex>".to_string());
            }
            let context = parse_context(&args[1])?;
            let bytes = decode_hex(&args[2])
                .map_err(|err| format!("invalid hex for response-apdu: {}", err.name()))?;
            decode_response_apdu(context, bytes)
        }
        "help" | "--help" | "-h" => Ok(format!("{}\n", usage())),
        _ => Err(format!("unknown decode mode: {mode}")),
    }
}

fn usage() -> &'static str {
    "usage: krn_emv_decode <tlv|dol|cvm-list|tvr|tsi|cid|gac|termcap|ttq|ctq|apdu> <hex>\n\
     usage: krn_emv_decode sw <context> <SW1SW2>\n\
     usage: krn_emv_decode response-apdu <context> <response-body-plus-SW1SW2>\n\
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

fn decode_gac_response(bytes: Vec<u8>) -> Result<String, String> {
    let response = parse_generate_ac_response(&bytes)
        .map_err(|err| format!("GENERATE AC response parse failed: {}", err.name()))?;
    let mut out = String::new();
    let _ = writeln!(out, "type=generate-ac-response");
    let _ = writeln!(
        out,
        "response_format={}",
        match bytes.first().copied() {
            Some(0x80) => "format-1-template-80",
            Some(0x77) => "format-2-template-77",
            _ => "unknown",
        }
    );
    let _ = writeln!(out, "cid_raw=0x{:02X}", response.cid.raw());
    let _ = writeln!(
        out,
        "cryptogram_type={}",
        cryptogram_type_name(response.cid.cryptogram_type())
    );
    let _ = writeln!(out, "application_cryptogram_len=8");
    let _ = writeln!(out, "atc_len=2");
    let _ = writeln!(
        out,
        "issuer_application_data_len={}",
        response.issuer_application_data.len()
    );
    let _ = writeln!(
        out,
        "icc_dynamic_number_len={}",
        response
            .icc_dynamic_number
            .as_ref()
            .map_or(0, |value| value.len())
    );
    let _ = writeln!(
        out,
        "signed_dynamic_application_data_len={}",
        response
            .signed_dynamic_application_data
            .as_ref()
            .map_or(0, |value| value.len())
    );
    let _ = writeln!(
        out,
        "data_policy=application_cryptogram_iad_dynamic_authentication_suppressed"
    );
    Ok(out)
}

fn decode_terminal_capabilities(bytes: Vec<u8>) -> Result<String, String> {
    let raw: [u8; 3] = bytes
        .try_into()
        .map_err(|_| "Terminal Capabilities must be exactly 3 bytes".to_string())?;
    let mut out = String::new();
    let _ = writeln!(out, "type=terminal-capabilities");
    let _ = writeln!(out, "raw={}", hex_upper(&raw));
    let _ = writeln!(
        out,
        "rfu_bits={}",
        raw.iter()
            .zip(TERMINAL_CAPABILITY_ALLOWED_MASKS)
            .any(|(byte, allowed)| byte & !allowed != 0)
    );
    append_set_bits(&mut out, &raw, &TERMINAL_CAPABILITY_BITS);
    Ok(out)
}

fn decode_profile_defined_bitmap(
    kind: &'static str,
    bytes: Vec<u8>,
    expected_len: usize,
) -> Result<String, String> {
    if bytes.len() != expected_len {
        return Err(format!("{kind} must be exactly {expected_len} bytes"));
    }
    let mut out = String::new();
    let _ = writeln!(out, "type={kind}");
    let _ = writeln!(out, "raw={}", hex_upper(&bytes));
    let _ = writeln!(out, "scheme_policy=profile-defined");
    append_profile_defined_bits(&mut out, &bytes);
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

fn append_profile_defined_bits(out: &mut String, raw: &[u8]) {
    let mut count = 0usize;
    for (byte_idx, byte) in raw.iter().enumerate() {
        for bit_idx in 0..8 {
            let mask = 0x80 >> bit_idx;
            if byte & mask != 0 {
                let _ = writeln!(out, "bit=byte{}.b{}", byte_idx + 1, bit_idx + 1);
                count += 1;
            }
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

fn decode_response_apdu(context: ApduContext, bytes: Vec<u8>) -> Result<String, String> {
    if bytes.len() < 2 {
        return Err("response-apdu requires at least SW1SW2".to_string());
    }
    let body_len = bytes.len() - 2;
    let body = &bytes[..body_len];
    let sw = StatusWord::new(bytes[body_len], bytes[body_len + 1]);
    let trace_context = response_trace_context(context, body.is_empty());
    let trace = mask_apdu_response(
        0,
        trace_context,
        body,
        [sw.sw1, sw.sw2],
        LogPolicy::production(),
    )
    .map_err(|err| format!("APDU response parse failed: {}", err.name()))?;

    let mut out = String::new();
    let _ = writeln!(out, "type=response-apdu");
    let _ = writeln!(out, "context={}", context_name(context));
    let _ = writeln!(out, "trace_context={}", trace_context_name(trace_context));
    let _ = writeln!(out, "sw={:02X}{:02X}", sw.sw1, sw.sw2);
    let _ = writeln!(out, "action={}", action_name(classify(context, sw)));
    let _ = writeln!(out, "body_len={body_len}");
    let _ = writeln!(out, "field_count={}", trace.fields.len());
    for field in &trace.fields {
        let _ = writeln!(
            out,
            "field={} value_policy={}",
            hex_upper(&field.tag),
            masked_value_policy(&field.value)
        );
    }
    let _ = writeln!(out, "data_policy=response_body_values_suppressed");
    Ok(out)
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

fn response_trace_context(context: ApduContext, empty_body: bool) -> ApduTraceContext {
    match (context, empty_body) {
        (ApduContext::GenerateAc, false) => ApduTraceContext::GenerateAcResponse,
        _ => ApduTraceContext::Generic,
    }
}

fn trace_context_name(context: ApduTraceContext) -> &'static str {
    match context {
        ApduTraceContext::Generic => "generic",
        ApduTraceContext::GenerateAcResponse => "generate-ac-response",
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

fn masked_value_policy(value: &MaskedValue) -> &'static str {
    match value {
        MaskedValue::Hex(_) => "hex-suppressed",
        MaskedValue::Pan(_) => "pan-masked-suppressed",
        MaskedValue::Suppressed(reason) => reason,
        MaskedValue::DebugHash { .. } => "debug-hash-suppressed",
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

const TERMINAL_CAPABILITY_ALLOWED_MASKS: [u8; 3] = [0xe0, 0xf8, 0xe8];

const TERMINAL_CAPABILITY_BITS: [BitName; 12] = [
    BitName {
        position: (0, 0x80),
        name: "manual-key-entry",
    },
    BitName {
        position: (0, 0x40),
        name: "magnetic-stripe",
    },
    BitName {
        position: (0, 0x20),
        name: "icc-with-contacts",
    },
    BitName {
        position: (1, 0x80),
        name: "plaintext-pin-for-icc-verification",
    },
    BitName {
        position: (1, 0x40),
        name: "enciphered-pin-for-online-verification",
    },
    BitName {
        position: (1, 0x20),
        name: "signature-paper",
    },
    BitName {
        position: (1, 0x10),
        name: "enciphered-pin-for-offline-verification",
    },
    BitName {
        position: (1, 0x08),
        name: "no-cvm-required",
    },
    BitName {
        position: (2, 0x80),
        name: "sda-supported",
    },
    BitName {
        position: (2, 0x40),
        name: "dda-supported",
    },
    BitName {
        position: (2, 0x20),
        name: "card-capture-supported",
    },
    BitName {
        position: (2, 0x08),
        name: "cda-supported",
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
    fn terminal_capabilities_output_names_standard_bits_and_flags_rfu() {
        let out = decode_terminal_capabilities(decode_hex("E0B0C8").unwrap()).unwrap();

        assert!(out.contains("type=terminal-capabilities"));
        assert!(out.contains("raw=E0B0C8"));
        assert!(out.contains("rfu_bits=false"));
        assert!(out.contains("bit=manual-key-entry"));
        assert!(out.contains("bit=icc-with-contacts"));
        assert!(out.contains("bit=plaintext-pin-for-icc-verification"));
        assert!(out.contains("bit=signature-paper"));
        assert!(out.contains("bit=cda-supported"));

        let rfu = decode_terminal_capabilities(decode_hex("010001").unwrap()).unwrap();
        assert!(rfu.contains("rfu_bits=true"));
    }

    #[test]
    fn ttq_and_ctq_output_profile_defined_bitmaps() {
        let ttq = decode_profile_defined_bitmap("ttq", decode_hex("36004000").unwrap(), 4).unwrap();
        let ctq = decode_profile_defined_bitmap("ctq", decode_hex("20").unwrap(), 1).unwrap();

        assert!(ttq.contains("type=ttq"));
        assert!(ttq.contains("scheme_policy=profile-defined"));
        assert!(ttq.contains("bit=byte1.b3"));
        assert!(ttq.contains("bit=byte1.b4"));
        assert!(ttq.contains("bit=byte3.b2"));
        assert!(ctq.contains("type=ctq"));
        assert!(ctq.contains("scheme_policy=profile-defined"));
        assert!(ctq.contains("bit=byte1.b3"));

        assert_eq!(
            decode_profile_defined_bitmap("ttq", decode_hex("3600").unwrap(), 4).unwrap_err(),
            "ttq must be exactly 4 bytes"
        );
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
    fn gac_response_output_parses_without_exposing_values() {
        let out = decode_gac_response(
            decode_hex("771A9F2701809F360200099F260811121314151617189F1003AABBCC").unwrap(),
        )
        .unwrap();

        assert!(out.contains("type=generate-ac-response"));
        assert!(out.contains("response_format=format-2-template-77"));
        assert!(out.contains("cid_raw=0x80"));
        assert!(out.contains("cryptogram_type=arqc"));
        assert!(out.contains("application_cryptogram_len=8"));
        assert!(out.contains("atc_len=2"));
        assert!(out.contains("issuer_application_data_len=3"));
        assert!(out.contains("icc_dynamic_number_len=0"));
        assert!(out.contains("signed_dynamic_application_data_len=0"));
        assert!(out
            .contains("data_policy=application_cryptogram_iad_dynamic_authentication_suppressed"));
        assert!(!out.contains("1112131415161718"));
        assert!(!out.contains("AABBCC"));
    }

    #[test]
    fn gac_response_output_rejects_unwrapped_response_data() {
        assert!(decode_gac_response(
            decode_hex("9F2701809F360200099F260811121314151617189F1003AABBCC").unwrap()
        )
        .unwrap_err()
        .contains("KRN_ERR_MISSING_MANDATORY_TAG"));
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
    fn response_apdu_output_masks_tlv_fields_and_classifies_status() {
        let out = decode_response_apdu(
            ApduContext::ReadRecord,
            decode_hex("700A5A08123456789012345F9000").unwrap(),
        )
        .unwrap();

        assert!(out.contains("type=response-apdu"));
        assert!(out.contains("context=read-record"));
        assert!(out.contains("trace_context=generic"));
        assert!(out.contains("sw=9000"));
        assert!(out.contains("action=success"));
        assert!(out.contains("body_len=12"));
        assert!(out.contains("field=70 value_policy=constructed"));
        assert!(out.contains("field=5A value_policy=pan-masked-suppressed"));
        assert!(out.contains("data_policy=response_body_values_suppressed"));
        assert!(!out.contains("123456789012345F"));
    }

    #[test]
    fn response_apdu_generate_ac_uses_gac_masking_policy() {
        let out = decode_response_apdu(
            ApduContext::GenerateAc,
            decode_hex("771A9F2701809F360200099F260811121314151617189F1003AABBCC9000").unwrap(),
        )
        .unwrap();

        assert!(out.contains("trace_context=generate-ac-response"));
        assert!(out.contains("field=9F26 value_policy=transaction-cryptogram"));
        assert!(out.contains("field=9F10 value_policy=issuer-application-data"));
        assert!(out.contains("field_count=4"));
        assert!(!out.contains("1112131415161718"));
        assert!(!out.contains("AABBCC"));
    }

    #[test]
    fn response_apdu_status_only_errors_do_not_require_body_parsing() {
        let out =
            decode_response_apdu(ApduContext::GenerateAc, decode_hex("6985").unwrap()).unwrap();

        assert!(out.contains("type=response-apdu"));
        assert!(out.contains("context=generate-ac"));
        assert!(out.contains("trace_context=generic"));
        assert!(out.contains("sw=6985"));
        assert!(out.contains("action=fail error=KRN_ERR_CARD_REMOVED"));
        assert!(out.contains("body_len=0"));
        assert!(out.contains("field_count=0"));
        assert!(out.contains("data_policy=response_body_values_suppressed"));
    }

    #[test]
    fn malformed_response_apdu_is_rejected() {
        assert_eq!(
            decode_response_apdu(ApduContext::ReadRecord, vec![0x90]).unwrap_err(),
            "response-apdu requires at least SW1SW2"
        );
        assert!(decode_response_apdu(
            ApduContext::ReadRecord,
            decode_hex("700A5A08123456789012345F00").unwrap()
        )
        .unwrap_err()
        .contains("KRN_ERR_LENGTH_OVERFLOW"));
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
    fn cli_routes_response_apdu_mode() {
        let out = run(&[
            string_arg("response-apdu"),
            string_arg("generate-ac"),
            string_arg("800B40123410111213141516179000"),
        ])
        .unwrap();

        assert!(out.contains("type=response-apdu"));
        assert!(out.contains("trace_context=generate-ac-response"));
        assert!(out.contains("sw=9000"));
        assert!(out.contains("action=success"));
        assert!(!out.contains("1011121314151617"));
    }

    #[test]
    fn cli_routes_cid_mode() {
        let out = run(&[string_arg("cid"), string_arg("47")]).unwrap();

        assert!(out.contains("type=cid"));
        assert!(out.contains("cryptogram_type=tc"));
    }

    #[test]
    fn cli_routes_gac_mode() {
        let out = run(&[string_arg("gac"), string_arg("800B4012341011121314151617")]).unwrap();

        assert!(out.contains("type=generate-ac-response"));
        assert!(out.contains("response_format=format-1-template-80"));
        assert!(out.contains("cryptogram_type=tc"));
        assert!(!out.contains("1011121314151617"));
    }

    #[test]
    fn cli_routes_profile_bitmap_modes() {
        let out = run(&[string_arg("ttq"), string_arg("36004000")]).unwrap();

        assert!(out.contains("type=ttq"));
        assert!(out.contains("scheme_policy=profile-defined"));
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
