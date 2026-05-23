use hyperion_emv::aip::ApplicationInterchangeProfile;
use hyperion_emv::cid::{Cid, CryptogramType};
use hyperion_emv::config::decode_hex;
use hyperion_emv::cvm::{parse_cvm_list, CvmMethod, CvmResultStatus, CvmResults};
use hyperion_emv::dol::parse_dol;
use hyperion_emv::gac::parse_generate_ac_response;
use hyperion_emv::issuer::{parse_host_response, ScriptPhase};
use hyperion_emv::numeric::{bcd_digits, decode_numeric_bcd_fixed};
use hyperion_emv::record::summarize_track2_equivalent_data;
use hyperion_emv::restrictions::{ApplicationUsageControl, EmvDate};
use hyperion_emv::state::{Tsi, Tvr};
use hyperion_emv::sw::{classify, ApduContext, StatusAction, StatusWord};
use hyperion_emv::terminal::{TerminalCapabilities, TerminalType, TERMINAL_CAPABILITY_BITS};
use hyperion_emv::tlv;
use hyperion_emv::trace::{mask_apdu_response, ApduTraceContext, LogPolicy, MaskedValue};
use hyperion_emv::transaction::{CurrencyExponent, TransactionType};
use std::fmt::Write;
use std::process;

const MAX_DECODE_TAG_LIST_TAGS: usize = 64;
const TLV_CATALOGUE: &str = include_str!("../docs/tlv_catalogue.csv");

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
        "tag-list" => decode_tag_list(arg_hex(args, 1, "tag-list")?),
        "numeric-code" => decode_numeric_code(arg_hex(args, 1, "numeric-code")?),
        "amount" | "amount-authorised" | "amount-other" => decode_amount(arg_hex(args, 1, mode)?),
        "track2" | "track2-equivalent" => decode_track2(arg_hex(args, 1, mode)?),
        "date"
        | "transaction-date"
        | "application-expiration-date"
        | "application-effective-date" => decode_date(arg_hex(args, 1, mode)?),
        "currency-exponent" => decode_currency_exponent(arg_hex(args, 1, "currency-exponent")?),
        "transaction-type" => decode_transaction_type(arg_hex(args, 1, "transaction-type")?),
        "terminal-type" => decode_terminal_type(arg_hex(args, 1, "terminal-type")?),
        "aip" => decode_aip(arg_hex(args, 1, "aip")?),
        "auc" | "application-usage-control" => {
            decode_application_usage_control(arg_hex(args, 1, "auc")?)
        }
        "cvm-list" => decode_cvm_list(arg_hex(args, 1, "cvm-list")?),
        "cvm-results" => decode_cvm_results(arg_hex(args, 1, "cvm-results")?),
        "tvr" => decode_tvr(arg_hex(args, 1, "tvr")?),
        "tsi" => decode_tsi(arg_hex(args, 1, "tsi")?),
        "cid" => decode_cid(arg_hex(args, 1, "cid")?),
        "gac" | "generate-ac-response" => decode_gac_response(arg_hex(args, 1, "gac")?),
        "host-response" => decode_host_response(arg_hex(args, 1, "host-response")?),
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
    "usage: krn_emv_decode <tlv|dol|tag-list|numeric-code|amount|track2|date|currency-exponent|transaction-type|terminal-type|aip|auc|cvm-list|cvm-results|tvr|tsi|cid|gac|host-response|termcap|ttq|ctq|apdu> <hex>\n\
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
        let _ = write!(
            out,
            "tag={} constructed={} len={} value_policy=suppressed",
            hex_upper(node.tag),
            node.constructed,
            node.value.len()
        );
        append_catalogue_metadata(&mut out, node.tag);
        let _ = writeln!(out);
    }
    Ok(out)
}

fn decode_dol(bytes: Vec<u8>) -> Result<String, String> {
    let entries = parse_dol(&bytes).map_err(|err| format!("DOL parse failed: {}", err.name()))?;
    let mut out = String::new();
    let _ = writeln!(out, "type=dol");
    let _ = writeln!(out, "count={}", entries.len());
    for entry in entries {
        let _ = write!(out, "tag={} len={}", hex_upper(&entry.tag), entry.length);
        append_catalogue_metadata(&mut out, &entry.tag);
        let _ = writeln!(out);
    }
    Ok(out)
}

fn decode_tag_list(bytes: Vec<u8>) -> Result<String, String> {
    let tags = tlv::parse_unique_primitive_tag_list(&bytes, MAX_DECODE_TAG_LIST_TAGS)
        .map_err(|err| format!("tag-list parse failed: {}", err.name()))?;
    let mut out = String::new();
    let _ = writeln!(out, "type=tag-list");
    let _ = writeln!(out, "count={}", tags.len());
    for tag in tags {
        let _ = write!(out, "tag={}", hex_upper(&tag));
        append_catalogue_metadata(&mut out, &tag);
        let _ = writeln!(out);
    }
    let _ = writeln!(out, "value_policy=not-applicable");
    Ok(out)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CatalogueEntry<'a> {
    name: &'a str,
    tag_type: &'a str,
    length_rule: &'a str,
    classification: &'a str,
}

fn append_catalogue_metadata(out: &mut String, tag: &[u8]) {
    match catalogue_entry_for(tag) {
        Some(entry) => {
            let _ = write!(
                out,
                " catalogue=hit name=\"{}\" tag_type=\"{}\" length_rule=\"{}\" classification={}",
                entry.name, entry.tag_type, entry.length_rule, entry.classification
            );
        }
        None => {
            let _ = write!(out, " catalogue=missing");
        }
    }
}

fn catalogue_entry_for(tag: &[u8]) -> Option<CatalogueEntry<'static>> {
    let tag_hex = hex_upper(tag);
    TLV_CATALOGUE.lines().skip(1).find_map(|line| {
        let columns = line.split(',').collect::<Vec<_>>();
        (columns.len() == 10 && columns[0] == tag_hex).then_some(CatalogueEntry {
            name: columns[1],
            tag_type: columns[2],
            length_rule: columns[3],
            classification: columns[8],
        })
    })
}

fn decode_numeric_code(bytes: Vec<u8>) -> Result<String, String> {
    let raw: [u8; 2] = bytes
        .try_into()
        .map_err(|_| "numeric-code must be exactly 2 BCD bytes".to_string())?;
    let digits =
        bcd_digits(&raw).map_err(|_| "numeric-code contains non-BCD nibbles".to_string())?;
    if digits[0] != 0 {
        return Err("numeric-code must encode a three-digit value as 0XXX BCD".to_string());
    }
    let value = u16::from(digits[1]) * 100 + u16::from(digits[2]) * 10 + u16::from(digits[3]);

    let mut out = String::new();
    let _ = writeln!(out, "type=numeric-code");
    let _ = writeln!(out, "raw={}", hex_upper(&raw));
    let _ = writeln!(
        out,
        "digits={}{}{}{}",
        digits[0], digits[1], digits[2], digits[3]
    );
    let _ = writeln!(out, "code={value:03}");
    let _ = writeln!(out, "field_shape=three-digit-code-in-two-byte-bcd");
    let _ = writeln!(out, "authority=profile-or-lab-defined");
    let _ = writeln!(out, "value_policy=non-sensitive");
    Ok(out)
}

fn decode_amount(bytes: Vec<u8>) -> Result<String, String> {
    let raw: [u8; 6] = bytes
        .try_into()
        .map_err(|_| "amount must be exactly 6 BCD bytes".to_string())?;
    let minor_units = decode_numeric_bcd_fixed(&raw)
        .map_err(|_| "amount contains non-BCD nibbles".to_string())?;
    let digits = bcd_digits(&raw).map_err(|_| "amount contains non-BCD nibbles".to_string())?;

    let mut out = String::new();
    let _ = writeln!(out, "type=amount");
    let _ = writeln!(out, "raw={}", hex_upper(&raw));
    let _ = writeln!(out, "digits={}", digit_string(&digits));
    let _ = writeln!(out, "minor_units={minor_units}");
    let _ = writeln!(out, "field_shape=six-byte-fixed-numeric-bcd");
    let _ = writeln!(out, "authority=runtime-amount-minor-unit-mapping");
    let _ = writeln!(out, "value_policy=non-sensitive");
    Ok(out)
}

fn decode_track2(bytes: Vec<u8>) -> Result<String, String> {
    let summary = summarize_track2_equivalent_data(&bytes)
        .map_err(|err| format!("Track 2 Equivalent Data parse failed: {}", err.name()))?;

    let mut out = String::new();
    let _ = writeln!(out, "type=track2-equivalent");
    let _ = writeln!(out, "raw_len={}", bytes.len());
    let _ = writeln!(out, "pan_digit_count={}", summary.pan_digit_count);
    let _ = writeln!(
        out,
        "post_separator_digit_count={}",
        summary.post_separator_digit_count
    );
    let _ = writeln!(out, "expiration_date_present=true");
    let _ = writeln!(out, "service_code_present=true");
    let _ = writeln!(
        out,
        "discretionary_digit_count={}",
        summary.discretionary_digit_count
    );
    let _ = writeln!(out, "padded={}", summary.padded);
    let _ = writeln!(out, "authority=runtime-read-record-cardholder-data-parser");
    let _ = writeln!(
        out,
        "value_policy=pan_expiration_service_code_discretionary_digits_suppressed"
    );
    Ok(out)
}

fn decode_date(bytes: Vec<u8>) -> Result<String, String> {
    let raw: [u8; 3] = bytes
        .try_into()
        .map_err(|_| "date must be exactly 3 YYMMDD BCD bytes".to_string())?;
    let date =
        EmvDate::from_bcd(raw).map_err(|err| format!("date parse failed: {}", err.name()))?;

    let mut out = String::new();
    let _ = writeln!(out, "type=date");
    let _ = writeln!(out, "raw={}", hex_upper(&raw));
    let _ = writeln!(out, "emv_yy={:02}", date.year);
    let _ = writeln!(out, "month={:02}", date.month);
    let _ = writeln!(out, "day={:02}", date.day);
    let _ = writeln!(
        out,
        "profile_date=20{:02}-{:02}-{:02}",
        date.year, date.month, date.day
    );
    let _ = writeln!(out, "field_shape=three-byte-YYMMDD-bcd");
    let _ = writeln!(out, "authority=runtime-processing-restrictions-date-parser");
    let _ = writeln!(out, "value_policy=non-sensitive");
    Ok(out)
}

fn decode_currency_exponent(bytes: Vec<u8>) -> Result<String, String> {
    let raw: [u8; 1] = bytes
        .try_into()
        .map_err(|_| "currency-exponent must be exactly 1 byte".to_string())?;
    let exponent = CurrencyExponent::parse(&raw)
        .map_err(|err| format!("currency-exponent parse failed: {}", err.name()))?;

    let mut out = String::new();
    let _ = writeln!(out, "type=currency-exponent");
    let _ = writeln!(out, "raw=0x{:02X}", raw[0]);
    let _ = writeln!(out, "exponent={}", exponent.value());
    let _ = writeln!(out, "amount_scale=10^-{}", exponent.value());
    let _ = writeln!(out, "authority=runtime-transaction-parameter-validation");
    let _ = writeln!(out, "value_policy=non-sensitive");
    Ok(out)
}

fn decode_transaction_type(bytes: Vec<u8>) -> Result<String, String> {
    let raw: [u8; 1] = bytes
        .try_into()
        .map_err(|_| "transaction-type must be exactly 1 byte".to_string())?;
    let transaction_type = TransactionType::parse(&raw)
        .map_err(|err| format!("transaction-type parse failed: {}", err.name()))?;

    let mut out = String::new();
    let _ = writeln!(out, "type=transaction-type");
    let _ = writeln!(out, "raw=0x{:02X}", transaction_type.raw());
    let _ = writeln!(
        out,
        "runtime_service={}",
        transaction_type.runtime_service().label()
    );
    let _ = writeln!(
        out,
        "cvm_condition_non_atm={}",
        transaction_type.cvm_transaction_class(false).label()
    );
    let _ = writeln!(
        out,
        "cvm_condition_atm={}",
        transaction_type.cvm_transaction_class(true).label()
    );
    let _ = writeln!(out, "authority={}", transaction_type.mapping_authority());
    let _ = writeln!(out, "value_policy=non-sensitive");
    Ok(out)
}

fn decode_terminal_type(bytes: Vec<u8>) -> Result<String, String> {
    let raw: [u8; 1] = bytes
        .try_into()
        .map_err(|_| "terminal-type must be exactly 1 byte".to_string())?;
    let terminal_type = TerminalType::parse(raw[0])
        .map_err(|err| format!("terminal-type parse failed: {}", err.name()))?;

    let mut out = String::new();
    let _ = writeln!(out, "type=terminal-type");
    let _ = writeln!(out, "raw=0x{:02X}", terminal_type.raw());
    let _ = writeln!(out, "operator={}", terminal_type.operator().label());
    let _ = writeln!(out, "location={}", terminal_type.location().label());
    let _ = writeln!(out, "online_capable={}", terminal_type.online_capable());
    let _ = writeln!(out, "authority=emv-profile-defined");
    let _ = writeln!(out, "value_policy=non-sensitive");
    Ok(out)
}

fn decode_aip(bytes: Vec<u8>) -> Result<String, String> {
    let aip = ApplicationInterchangeProfile::parse(&bytes)
        .map_err(|err| format!("AIP parse failed: {}", err.name()))?;

    let mut out = String::new();
    let _ = writeln!(out, "type=aip");
    let _ = writeln!(out, "raw={}", hex_upper(&aip.raw()));
    let _ = writeln!(out, "sda_supported={}", aip.sda_supported());
    let _ = writeln!(out, "dda_supported={}", aip.dda_supported());
    let _ = writeln!(out, "cda_supported={}", aip.cda_supported());
    let _ = writeln!(out, "oda_required={}", aip.oda_required());
    let _ = writeln!(out, "authority=runtime-profile-mapping");
    let _ = writeln!(out, "value_policy=non-sensitive");
    Ok(out)
}

fn decode_application_usage_control(bytes: Vec<u8>) -> Result<String, String> {
    let auc = ApplicationUsageControl::parse(&bytes)
        .map_err(|err| format!("AUC parse failed: {}", err.name()))?;

    let mut out = String::new();
    let _ = writeln!(out, "type=application-usage-control");
    let _ = writeln!(out, "raw={}", hex_upper(&auc.raw()));
    let _ = writeln!(out, "domestic_cash={}", auc.valid_for_domestic_cash());
    let _ = writeln!(
        out,
        "international_cash={}",
        auc.valid_for_international_cash()
    );
    let _ = writeln!(out, "domestic_goods={}", auc.valid_for_domestic_goods());
    let _ = writeln!(
        out,
        "international_goods={}",
        auc.valid_for_international_goods()
    );
    let _ = writeln!(
        out,
        "domestic_services={}",
        auc.valid_for_domestic_services()
    );
    let _ = writeln!(
        out,
        "international_services={}",
        auc.valid_for_international_services()
    );
    let _ = writeln!(out, "valid_at_atm={}", auc.valid_at_atm());
    let _ = writeln!(out, "valid_other_than_atm={}", auc.valid_other_than_atm());
    let _ = writeln!(
        out,
        "domestic_cashback={}",
        auc.valid_for_domestic_cashback()
    );
    let _ = writeln!(
        out,
        "international_cashback={}",
        auc.valid_for_international_cashback()
    );
    let _ = writeln!(out, "byte2_rfu_mask=0x{:02X}", auc.byte2_rfu_mask());
    let _ = writeln!(out, "authority=runtime-processing-restrictions-mapping");
    let _ = writeln!(out, "value_policy=non-sensitive");
    Ok(out)
}

fn digit_string(digits: &[u8]) -> String {
    digits
        .iter()
        .map(|digit| char::from(b'0' + *digit))
        .collect()
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

fn decode_cvm_results(bytes: Vec<u8>) -> Result<String, String> {
    let results = CvmResults::parse(&bytes)
        .map_err(|err| format!("CVM Results parse failed: {}", err.name()))?;
    let mut out = String::new();
    let _ = writeln!(out, "type=cvm-results");
    let _ = writeln!(out, "raw={}", hex_upper(&results.raw()));
    let _ = writeln!(out, "method={}", cvm_method_name(results.method()));
    let _ = writeln!(out, "condition=0x{:02X}", results.condition_code());
    let _ = writeln!(out, "result={}", cvm_result_status_name(results.result()));
    let _ = writeln!(out, "result_code=0x{:02X}", results.result().code());
    let _ = writeln!(out, "authority=runtime-cvm-results-mapping");
    let _ = writeln!(out, "value_policy=non-sensitive");
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

fn decode_host_response(bytes: Vec<u8>) -> Result<String, String> {
    let response = parse_host_response(&bytes)
        .map_err(|err| format!("host-response parse failed: {}", err.name()))?;

    let mut out = String::new();
    let _ = writeln!(out, "type=host-response");
    let _ = writeln!(
        out,
        "authorization_response_code={}",
        hex_upper(&response.authorization_response_code)
    );
    let _ = writeln!(
        out,
        "authorization_code_present={}",
        response.authorization_code.is_some()
    );
    let _ = writeln!(
        out,
        "issuer_authentication_data_len={}",
        response
            .issuer_authentication_data
            .as_ref()
            .map_or(0, Vec::len)
    );
    let _ = writeln!(out, "script_count={}", response.scripts.len());
    for (idx, script) in response.scripts.iter().enumerate() {
        let command_lengths = script
            .commands
            .iter()
            .map(Vec::len)
            .map(|len| len.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let _ = writeln!(
            out,
            "script={} phase={} identifier_present={} command_count={} command_lengths={}",
            idx,
            script_phase_name(script.phase),
            script.identifier.is_some(),
            script.commands.len(),
            command_lengths
        );
    }
    let _ = writeln!(
        out,
        "data_policy=issuer_authentication_data_and_script_bytes_suppressed"
    );
    let _ = writeln!(out, "value_policy=non-sensitive-control-fields-only");
    Ok(out)
}

fn decode_terminal_capabilities(bytes: Vec<u8>) -> Result<String, String> {
    let capabilities = TerminalCapabilities::parse(&bytes)
        .map_err(|_| "Terminal Capabilities must be exactly 3 bytes".to_string())?;
    let mut out = String::new();
    let _ = writeln!(out, "type=terminal-capabilities");
    let _ = writeln!(out, "raw={}", hex_upper(&capabilities.raw()));
    let _ = writeln!(out, "rfu_bits={}", capabilities.has_rfu_bits());
    append_terminal_capability_bits(&mut out, capabilities);
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

fn append_terminal_capability_bits(out: &mut String, capabilities: TerminalCapabilities) {
    let mut count = 0usize;
    for bit in TERMINAL_CAPABILITY_BITS {
        if capabilities.bit_is_set(bit) {
            let _ = writeln!(out, "bit={}", bit.name());
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

fn cvm_result_status_name(status: CvmResultStatus) -> String {
    match status {
        CvmResultStatus::Unknown => "unknown".to_string(),
        CvmResultStatus::Failed => "failed".to_string(),
        CvmResultStatus::Successful => "successful".to_string(),
        CvmResultStatus::Other(code) => format!("other-0x{code:02X}"),
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

fn script_phase_name(phase: ScriptPhase) -> &'static str {
    match phase {
        ScriptPhase::BeforeFinalGenerateAc => "before-final-generate-ac",
        ScriptPhase::AfterFinalGenerateAc => "after-final-generate-ac",
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
        assert!(out.contains(
            "tag=5A constructed=false len=8 value_policy=suppressed catalogue=hit name=\"PAN\""
        ));
        assert!(out.contains("classification=cardholder-data"));
        assert!(out.contains("value_policy=suppressed"));
        assert!(!out.contains("123456789012345F"));
    }

    #[test]
    fn dol_output_lists_tags_and_lengths() {
        let out = decode_dol(decode_hex("9F66049F02069A03").unwrap()).unwrap();

        assert!(out.contains("type=dol"));
        assert!(out.contains(
            "tag=9F66 len=4 catalogue=hit name=\"Terminal Transaction Qualifiers (TTQ)\""
        ));
        assert!(out.contains("tag=9F02 len=6 catalogue=hit name=\"Amount Authorised\""));
        assert!(out.contains("tag=9A len=3 catalogue=hit name=\"Transaction Date\""));
        assert!(out.contains("classification=profile-defined"));
        assert!(out.contains("classification=non-sensitive"));
    }

    #[test]
    fn tag_list_output_lists_primitive_tags_without_values() {
        let out = decode_tag_list(decode_hex("829F375F2A").unwrap()).unwrap();

        assert!(out.contains("type=tag-list"));
        assert!(out.contains("count=3"));
        assert!(out.contains("tag=82 catalogue=hit name=\"Application Interchange Profile (AIP)\""));
        assert!(out.contains("tag=9F37 catalogue=hit name=\"Unpredictable Number\""));
        assert!(out.contains("tag=5F2A catalogue=hit name=\"Transaction Currency Code\""));
        assert!(out.contains("value_policy=not-applicable"));
        assert!(!out.contains("len="));
    }

    #[test]
    fn tag_list_output_rejects_malformed_or_constructed_entries() {
        assert!(decode_tag_list(decode_hex("A5").unwrap())
            .unwrap_err()
            .contains("KRN_ERR_PARSE_ERROR"));
        assert!(decode_tag_list(decode_hex("8282").unwrap())
            .unwrap_err()
            .contains("KRN_ERR_PARSE_ERROR"));
    }

    #[test]
    fn numeric_code_output_enforces_three_digit_bcd_shape() {
        let out = decode_numeric_code(decode_hex("0840").unwrap()).unwrap();

        assert!(out.contains("type=numeric-code"));
        assert!(out.contains("raw=0840"));
        assert!(out.contains("digits=0840"));
        assert!(out.contains("code=840"));
        assert!(out.contains("field_shape=three-digit-code-in-two-byte-bcd"));
        assert!(out.contains("authority=profile-or-lab-defined"));
        assert!(out.contains("value_policy=non-sensitive"));

        assert_eq!(
            decode_numeric_code(vec![0x08]).unwrap_err(),
            "numeric-code must be exactly 2 BCD bytes"
        );
        assert_eq!(
            decode_numeric_code(decode_hex("0A40").unwrap()).unwrap_err(),
            "numeric-code contains non-BCD nibbles"
        );
        assert_eq!(
            decode_numeric_code(decode_hex("1234").unwrap()).unwrap_err(),
            "numeric-code must encode a three-digit value as 0XXX BCD"
        );
    }

    #[test]
    fn amount_output_decodes_minor_units_without_exponent_assumption() {
        let out = decode_amount(decode_hex("000000001234").unwrap()).unwrap();

        assert!(out.contains("type=amount"));
        assert!(out.contains("raw=000000001234"));
        assert!(out.contains("digits=000000001234"));
        assert!(out.contains("minor_units=1234"));
        assert!(out.contains("field_shape=six-byte-fixed-numeric-bcd"));
        assert!(out.contains("authority=runtime-amount-minor-unit-mapping"));
        assert!(out.contains("value_policy=non-sensitive"));
        assert!(!out.contains("currency"));
        assert!(!out.contains("decimal"));

        assert_eq!(
            decode_amount(vec![0x00, 0x00, 0x00, 0x12, 0x34]).unwrap_err(),
            "amount must be exactly 6 BCD bytes"
        );
        assert_eq!(
            decode_amount(decode_hex("0000000A1234").unwrap()).unwrap_err(),
            "amount contains non-BCD nibbles"
        );
    }

    #[test]
    fn track2_output_reports_shape_without_values() {
        let out = decode_track2(decode_hex("123456789012D25122012345678F").unwrap()).unwrap();

        assert!(out.contains("type=track2-equivalent"));
        assert!(out.contains("raw_len=14"));
        assert!(out.contains("pan_digit_count=12"));
        assert!(out.contains("post_separator_digit_count=14"));
        assert!(out.contains("expiration_date_present=true"));
        assert!(out.contains("service_code_present=true"));
        assert!(out.contains("discretionary_digit_count=7"));
        assert!(out.contains("padded=true"));
        assert!(out.contains("authority=runtime-read-record-cardholder-data-parser"));
        assert!(out
            .contains("value_policy=pan_expiration_service_code_discretionary_digits_suppressed"));
        assert!(!out.contains("123456789012"));
        assert!(!out.contains("2512"));
        assert!(!out.contains("201"));
        assert!(!out.contains("2345678"));

        assert!(decode_track2(decode_hex("123456").unwrap())
            .unwrap_err()
            .contains("KRN_ERR_PARSE_ERROR"));
    }

    #[test]
    fn date_output_uses_runtime_calendar_validation() {
        let out = decode_date(decode_hex("260523").unwrap()).unwrap();

        assert!(out.contains("type=date"));
        assert!(out.contains("raw=260523"));
        assert!(out.contains("emv_yy=26"));
        assert!(out.contains("month=05"));
        assert!(out.contains("day=23"));
        assert!(out.contains("profile_date=2026-05-23"));
        assert!(out.contains("field_shape=three-byte-YYMMDD-bcd"));
        assert!(out.contains("authority=runtime-processing-restrictions-date-parser"));
        assert!(out.contains("value_policy=non-sensitive"));

        assert_eq!(
            decode_date(vec![0x26, 0x05]).unwrap_err(),
            "date must be exactly 3 YYMMDD BCD bytes"
        );
        assert_eq!(
            decode_date(decode_hex("260A23").unwrap()).unwrap_err(),
            "date parse failed: KRN_ERR_PARSE_ERROR"
        );
        assert_eq!(
            decode_date(decode_hex("250229").unwrap()).unwrap_err(),
            "date parse failed: KRN_ERR_PARSE_ERROR"
        );

        let leap = decode_date(decode_hex("240229").unwrap()).unwrap();
        assert!(leap.contains("profile_date=2024-02-29"));
    }

    #[test]
    fn currency_exponent_output_uses_runtime_param_validation() {
        let out = decode_currency_exponent(decode_hex("02").unwrap()).unwrap();

        assert!(out.contains("type=currency-exponent"));
        assert!(out.contains("raw=0x02"));
        assert!(out.contains("exponent=2"));
        assert!(out.contains("amount_scale=10^-2"));
        assert!(out.contains("authority=runtime-transaction-parameter-validation"));
        assert!(out.contains("value_policy=non-sensitive"));

        assert_eq!(
            decode_currency_exponent(vec![]).unwrap_err(),
            "currency-exponent must be exactly 1 byte"
        );
        assert_eq!(
            decode_currency_exponent(decode_hex("0A").unwrap()).unwrap_err(),
            "currency-exponent parse failed: KRN_ERR_INVALID_ARGUMENT"
        );
    }

    #[test]
    fn transaction_type_output_exposes_runtime_service_mapping() {
        let out = decode_transaction_type(decode_hex("01").unwrap()).unwrap();

        assert!(out.contains("type=transaction-type"));
        assert!(out.contains("raw=0x01"));
        assert!(out.contains("runtime_service=cash"));
        assert!(out.contains("cvm_condition_non_atm=manual-cash"));
        assert!(out.contains("cvm_condition_atm=unattended-cash"));
        assert!(out.contains("authority=runtime-cvm-trm-service-mapping"));
        assert!(out.contains("value_policy=non-sensitive"));

        let cashback = decode_transaction_type(decode_hex("09").unwrap()).unwrap();
        assert!(cashback.contains("runtime_service=cashback"));
        assert!(cashback.contains("cvm_condition_non_atm=purchase-with-cashback"));

        let profile_defined = decode_transaction_type(decode_hex("99").unwrap()).unwrap();
        assert!(profile_defined.contains("runtime_service=goods-or-services"));
        assert!(profile_defined.contains("authority=profile-defined-or-unmapped"));

        assert_eq!(
            decode_transaction_type(vec![]).unwrap_err(),
            "transaction-type must be exactly 1 byte"
        );
    }

    #[test]
    fn terminal_type_output_names_emv_online_capability() {
        let out = decode_terminal_type(decode_hex("22").unwrap()).unwrap();

        assert!(out.contains("type=terminal-type"));
        assert!(out.contains("raw=0x22"));
        assert!(out.contains("operator=attended"));
        assert!(out.contains("location=merchant"));
        assert!(out.contains("online_capable=true"));
        assert!(out.contains("authority=emv-profile-defined"));
        assert!(out.contains("value_policy=non-sensitive"));

        let offline_only = decode_terminal_type(decode_hex("23").unwrap()).unwrap();
        assert!(offline_only.contains("online_capable=false"));

        assert_eq!(
            decode_terminal_type(Vec::new()).unwrap_err(),
            "terminal-type must be exactly 1 byte"
        );
        assert_eq!(
            decode_terminal_type(decode_hex("00").unwrap()).unwrap_err(),
            "terminal-type parse failed: KRN_ERR_INVALID_ARGUMENT"
        );
    }

    #[test]
    fn aip_output_names_runtime_oda_capabilities() {
        let out = decode_aip(decode_hex("C080").unwrap()).unwrap();

        assert!(out.contains("type=aip"));
        assert!(out.contains("raw=C080"));
        assert!(out.contains("sda_supported=true"));
        assert!(out.contains("dda_supported=true"));
        assert!(out.contains("cda_supported=true"));
        assert!(out.contains("oda_required=true"));
        assert!(out.contains("authority=runtime-profile-mapping"));
        assert!(out.contains("value_policy=non-sensitive"));

        let no_oda = decode_aip(decode_hex("0000").unwrap()).unwrap();
        assert!(no_oda.contains("oda_required=false"));

        assert_eq!(
            decode_aip(vec![0x80]).unwrap_err(),
            "AIP parse failed: KRN_ERR_MISSING_MANDATORY_TAG"
        );
    }

    #[test]
    fn auc_output_names_usage_control_bits_without_policy_override() {
        let out = decode_application_usage_control(decode_hex("FF80").unwrap()).unwrap();

        assert!(out.contains("type=application-usage-control"));
        assert!(out.contains("raw=FF80"));
        assert!(out.contains("domestic_cash=true"));
        assert!(out.contains("international_cash=true"));
        assert!(out.contains("domestic_goods=true"));
        assert!(out.contains("international_goods=true"));
        assert!(out.contains("domestic_services=true"));
        assert!(out.contains("international_services=true"));
        assert!(out.contains("valid_at_atm=true"));
        assert!(out.contains("valid_other_than_atm=true"));
        assert!(out.contains("domestic_cashback=true"));
        assert!(out.contains("international_cashback=false"));
        assert!(out.contains("byte2_rfu_mask=0x00"));
        assert!(out.contains("authority=runtime-processing-restrictions-mapping"));
        assert!(out.contains("value_policy=non-sensitive"));

        let rfu = decode_application_usage_control(decode_hex("0001").unwrap()).unwrap();
        assert!(rfu.contains("byte2_rfu_mask=0x01"));

        assert_eq!(
            decode_application_usage_control(vec![0xff]).unwrap_err(),
            "AUC parse failed: KRN_ERR_PARSE_ERROR"
        );
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
    fn cvm_results_output_names_method_condition_and_result() {
        let out = decode_cvm_results(decode_hex("420302").unwrap()).unwrap();

        assert!(out.contains("type=cvm-results"));
        assert!(out.contains("raw=420302"));
        assert!(out.contains("method=online-pin"));
        assert!(out.contains("condition=0x03"));
        assert!(out.contains("result=successful"));
        assert!(out.contains("result_code=0x02"));
        assert!(out.contains("authority=runtime-cvm-results-mapping"));
        assert!(out.contains("value_policy=non-sensitive"));

        let failed = decode_cvm_results(decode_hex("010001").unwrap()).unwrap();
        assert!(failed.contains("method=offline-plaintext-pin"));
        assert!(failed.contains("result=failed"));

        let other = decode_cvm_results(decode_hex("07007F").unwrap()).unwrap();
        assert!(other.contains("method=unknown-0x07"));
        assert!(other.contains("result=other-0x7F"));

        assert_eq!(
            decode_cvm_results(vec![0x01, 0x00]).unwrap_err(),
            "CVM Results parse failed: KRN_ERR_PARSE_ERROR"
        );
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
    fn host_response_output_suppresses_issuer_authentication_and_scripts() {
        let out = decode_host_response(
            decode_hex(
                "8A023030910811223344556677888906415050523031710F9F1804DEADBEEF860600DA000001AA7208860680E2000001BB",
            )
            .unwrap(),
        )
        .unwrap();

        assert!(out.contains("type=host-response"));
        assert!(out.contains("authorization_response_code=3030"));
        assert!(out.contains("authorization_code_present=true"));
        assert!(out.contains("issuer_authentication_data_len=8"));
        assert!(out.contains("script_count=2"));
        assert!(out.contains(
            "script=0 phase=before-final-generate-ac identifier_present=true command_count=1 command_lengths=6"
        ));
        assert!(out.contains(
            "script=1 phase=after-final-generate-ac identifier_present=false command_count=1 command_lengths=6"
        ));
        assert!(out.contains("data_policy=issuer_authentication_data_and_script_bytes_suppressed"));
        assert!(out.contains("value_policy=non-sensitive-control-fields-only"));
        for suppressed in [
            "1122334455667788",
            "415050523031",
            "DEADBEEF",
            "00DA",
            "80E2",
        ] {
            assert!(!out.contains(suppressed));
        }

        assert_eq!(
            decode_host_response(decode_hex("91081122334455667788").unwrap()).unwrap_err(),
            "host-response parse failed: KRN_ERR_MISSING_MANDATORY_TAG"
        );
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
    fn cli_routes_host_response_mode() {
        let out = run(&[
            string_arg("host-response"),
            string_arg("8A0230307108860600DA000001AA"),
        ])
        .unwrap();

        assert!(out.contains("type=host-response"));
        assert!(out.contains("authorization_response_code=3030"));
        assert!(out.contains("script_count=1"));
        assert!(!out.contains("00DA000001AA"));
    }

    #[test]
    fn cli_routes_tag_list_mode() {
        let out = run(&[string_arg("tag-list"), string_arg("829F37")]).unwrap();

        assert!(out.contains("type=tag-list"));
        assert!(out.contains("tag=9F37"));
    }

    #[test]
    fn cli_routes_numeric_code_mode() {
        let out = run(&[string_arg("numeric-code"), string_arg("0840")]).unwrap();

        assert!(out.contains("type=numeric-code"));
        assert!(out.contains("code=840"));
    }

    #[test]
    fn cli_routes_amount_mode() {
        let out = run(&[string_arg("amount"), string_arg("000000001234")]).unwrap();

        assert!(out.contains("type=amount"));
        assert!(out.contains("minor_units=1234"));
    }

    #[test]
    fn cli_routes_track2_mode() {
        let out = run(&[
            string_arg("track2"),
            string_arg("123456789012D25122012345678F"),
        ])
        .unwrap();

        assert!(out.contains("type=track2-equivalent"));
        assert!(out.contains("pan_digit_count=12"));
        assert!(!out.contains("123456789012"));
    }

    #[test]
    fn cli_routes_date_mode() {
        let out = run(&[string_arg("date"), string_arg("260523")]).unwrap();

        assert!(out.contains("type=date"));
        assert!(out.contains("profile_date=2026-05-23"));
    }

    #[test]
    fn cli_routes_currency_exponent_and_transaction_type_modes() {
        let exponent = run(&[string_arg("currency-exponent"), string_arg("02")]).unwrap();
        assert!(exponent.contains("type=currency-exponent"));
        assert!(exponent.contains("exponent=2"));

        let transaction_type = run(&[string_arg("transaction-type"), string_arg("09")]).unwrap();
        assert!(transaction_type.contains("type=transaction-type"));
        assert!(transaction_type.contains("runtime_service=cashback"));
    }

    #[test]
    fn cli_routes_terminal_type_mode() {
        let out = run(&[string_arg("terminal-type"), string_arg("22")]).unwrap();

        assert!(out.contains("type=terminal-type"));
        assert!(out.contains("online_capable=true"));
    }

    #[test]
    fn cli_routes_aip_mode() {
        let out = run(&[string_arg("aip"), string_arg("C080")]).unwrap();

        assert!(out.contains("type=aip"));
        assert!(out.contains("oda_required=true"));
    }

    #[test]
    fn cli_routes_auc_mode() {
        let out = run(&[string_arg("auc"), string_arg("FF80")]).unwrap();

        assert!(out.contains("type=application-usage-control"));
        assert!(out.contains("domestic_cashback=true"));
    }

    #[test]
    fn cli_routes_cvm_results_mode() {
        let out = run(&[string_arg("cvm-results"), string_arg("1F0002")]).unwrap();

        assert!(out.contains("type=cvm-results"));
        assert!(out.contains("method=no-cvm-required"));
        assert!(out.contains("result=successful"));
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
