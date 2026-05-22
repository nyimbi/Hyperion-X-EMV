use crate::error::{KernelError, KernelResult};
use crate::gac::{parse_generate_ac_response, GenerateAcResponse};
use crate::tlv;
use core::fmt::{self, Write};

pub const MAX_TRACE_FIELDS: usize = 128;
pub const MAX_REPLAY_STEPS: usize = 256;
pub const MAX_REPLAY_APDU_BYTES: usize = 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogBuildMode {
    Production,
    Certification,
    Development,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SupportAuthorization {
    Disabled,
    Verified,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LogPolicy {
    pub build_mode: LogBuildMode,
    pub support_authorization: SupportAuthorization,
    pub full_apdu: bool,
    pub track2_debug_hash: bool,
    pub transaction_cryptograms: bool,
}

impl LogPolicy {
    pub fn production() -> Self {
        Self {
            build_mode: LogBuildMode::Production,
            support_authorization: SupportAuthorization::Disabled,
            full_apdu: false,
            track2_debug_hash: false,
            transaction_cryptograms: false,
        }
    }

    pub fn certification_support() -> Self {
        Self {
            build_mode: LogBuildMode::Certification,
            support_authorization: SupportAuthorization::Verified,
            full_apdu: true,
            track2_debug_hash: true,
            transaction_cryptograms: false,
        }
    }

    fn support_verified(self) -> bool {
        self.support_authorization == SupportAuthorization::Verified
    }

    fn allows_full_apdu(self) -> bool {
        self.full_apdu
            && self.support_verified()
            && matches!(
                self.build_mode,
                LogBuildMode::Certification | LogBuildMode::Development
            )
    }

    fn allows_transaction_cryptograms(self) -> bool {
        self.transaction_cryptograms
            && self.support_verified()
            && self.build_mode != LogBuildMode::Production
    }

    fn allows_track2_hash(self) -> bool {
        self.track2_debug_hash && self.support_verified()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub enum MaskedValue {
    Hex(String),
    Pan(String),
    Suppressed(&'static str),
    DebugHash { len: usize, hash64: u64 },
}

impl fmt::Debug for MaskedValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MaskedValue::Hex(hex) => f
                .debug_struct("Hex")
                .field("hex_len", &hex.len())
                .field("data_policy", &"masked value redacted for crash safety")
                .finish(),
            MaskedValue::Pan(masked) => f
                .debug_struct("Pan")
                .field("masked_len", &masked.len())
                .field("data_policy", &"masked PAN redacted for crash safety")
                .finish(),
            MaskedValue::Suppressed(reason) => f
                .debug_struct("Suppressed")
                .field("reason", reason)
                .finish(),
            MaskedValue::DebugHash { len, .. } => f
                .debug_struct("DebugHash")
                .field("len", len)
                .field("data_policy", &"debug hash redacted for crash safety")
                .finish(),
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct MaskedField {
    pub tag: Vec<u8>,
    pub value: MaskedValue,
}

impl fmt::Debug for MaskedField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MaskedField")
            .field("tag", &self.tag)
            .field("value", &self.value)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApduTraceContext {
    Generic,
    GenerateAcResponse,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApduDirection {
    Command,
    Response,
}

#[derive(Clone, Eq, PartialEq)]
pub struct ApduTrace {
    pub sequence: u64,
    pub direction: ApduDirection,
    pub context: ApduTraceContext,
    pub cla: Option<u8>,
    pub ins: Option<u8>,
    pub p1: Option<u8>,
    pub p2: Option<u8>,
    pub sw: Option<[u8; 2]>,
    pub data: MaskedValue,
    pub fields: Vec<MaskedField>,
}

impl fmt::Debug for ApduTrace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApduTrace")
            .field("sequence", &self.sequence)
            .field("direction", &self.direction)
            .field("context", &self.context)
            .field("cla", &self.cla)
            .field("ins", &self.ins)
            .field("p1", &self.p1)
            .field("p2", &self.p2)
            .field("sw", &self.sw)
            .field("data", &self.data)
            .field("field_count", &self.fields.len())
            .field(
                "data_policy",
                &"trace payloads redacted from Debug; use to_json for controlled log emission",
            )
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ReplayExchange {
    pub command: Vec<u8>,
    pub response_data: Vec<u8>,
    pub sw: [u8; 2],
    pub context: ApduTraceContext,
}

impl fmt::Debug for ReplayExchange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReplayExchange")
            .field("command_len", &self.command.len())
            .field("response_data_len", &self.response_data.len())
            .field("sw", &self.sw)
            .field("context", &self.context)
            .field("data_policy", &"raw APDU bytes redacted for crash safety")
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TraceIdentity {
    pub kernel_name: &'static str,
    pub kernel_version: &'static str,
    pub abi_version: u32,
    pub profile_version: u64,
}

impl TraceIdentity {
    pub fn current(abi_version: u32, profile_version: u64) -> Self {
        Self {
            kernel_name: env!("CARGO_PKG_NAME"),
            kernel_version: env!("CARGO_PKG_VERSION"),
            abi_version,
            profile_version,
        }
    }
}

impl ReplayExchange {
    pub fn new(
        command: &[u8],
        response_data: &[u8],
        sw: [u8; 2],
        context: ApduTraceContext,
    ) -> KernelResult<Self> {
        validate_replay_apdu(command)?;
        validate_replay_apdu(response_data)?;
        if is_pin_verify_with_data(command) {
            return Err(KernelError::InvalidArgument);
        }
        Ok(Self {
            command: command.to_vec(),
            response_data: response_data.to_vec(),
            sw,
            context,
        })
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ReplayScript {
    steps: Vec<ReplayExchange>,
    cursor: usize,
}

impl fmt::Debug for ReplayScript {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReplayScript")
            .field("step_count", &self.steps.len())
            .field("cursor", &self.cursor)
            .field("data_policy", &"raw APDU bytes redacted for crash safety")
            .finish()
    }
}

impl ReplayScript {
    pub fn new(steps: Vec<ReplayExchange>) -> KernelResult<Self> {
        if steps.len() > MAX_REPLAY_STEPS {
            return Err(KernelError::LengthOverflow);
        }
        Ok(Self { steps, cursor: 0 })
    }

    pub fn reset(&mut self) {
        self.cursor = 0;
    }

    pub fn remaining(&self) -> usize {
        self.steps.len().saturating_sub(self.cursor)
    }

    pub fn exchange(&mut self, command: &[u8]) -> KernelResult<Vec<u8>> {
        let step = self.steps.get(self.cursor).ok_or(KernelError::ParseError)?;
        if step.command != command {
            return Err(KernelError::ParseError);
        }
        self.cursor += 1;

        let mut response = Vec::with_capacity(step.response_data.len() + 2);
        response.extend_from_slice(&step.response_data);
        response.extend_from_slice(&step.sw);
        Ok(response)
    }

    pub fn masked_jsonl(&self, policy: LogPolicy) -> KernelResult<String> {
        self.masked_jsonl_with_identity(policy, None)
    }

    pub fn masked_jsonl_with_trace_identity(
        &self,
        policy: LogPolicy,
        identity: &TraceIdentity,
    ) -> KernelResult<String> {
        self.masked_jsonl_with_identity(policy, Some(identity))
    }

    fn masked_jsonl_with_identity(
        &self,
        policy: LogPolicy,
        identity: Option<&TraceIdentity>,
    ) -> KernelResult<String> {
        let mut out = String::new();
        if let Some(identity) = identity {
            push_trace_identity_json(&mut out, identity, policy);
            out.push('\n');
        }
        for (idx, step) in self.steps.iter().enumerate() {
            let command = mask_apdu_command((idx as u64) * 2, &step.command, policy)?;
            command.push_json(&mut out);
            out.push('\n');

            let response = mask_apdu_response(
                (idx as u64) * 2 + 1,
                step.context,
                &step.response_data,
                step.sw,
                policy,
            )?;
            response.push_json(&mut out);
            out.push('\n');
        }
        Ok(out)
    }
}

pub fn mask_tlv_value(tag: &[u8], value: &[u8], policy: LogPolicy) -> MaskedField {
    let masked = if tag == [0x5a] {
        MaskedValue::Pan(mask_pan_bcd(value))
    } else if tag == [0x57] {
        if policy.allows_track2_hash() {
            MaskedValue::DebugHash {
                len: value.len(),
                hash64: fnv1a64(value),
            }
        } else {
            MaskedValue::Suppressed("track2")
        }
    } else if tag == [0x9f, 0x26] || tag == [0x91] {
        if policy.allows_transaction_cryptograms() {
            MaskedValue::Hex(to_hex(value))
        } else {
            MaskedValue::Suppressed("transaction-cryptogram")
        }
    } else if tag == [0x99] {
        MaskedValue::Suppressed("pin-block")
    } else {
        MaskedValue::Hex(to_hex(value))
    };

    MaskedField {
        tag: tag.to_vec(),
        value: masked,
    }
}

pub fn mask_tlv_stream(input: &[u8], policy: LogPolicy) -> KernelResult<Vec<MaskedField>> {
    let parsed = tlv::parse_many(input)?;
    let flat = tlv::flatten(&parsed);
    if flat.len() > MAX_TRACE_FIELDS {
        return Err(KernelError::LengthOverflow);
    }

    let mut out = Vec::with_capacity(flat.len());
    for item in flat {
        let field = if item.constructed {
            MaskedField {
                tag: item.tag.to_vec(),
                value: MaskedValue::Suppressed("constructed"),
            }
        } else {
            mask_tlv_value(item.tag, item.value, policy)
        };
        out.push(field);
    }
    Ok(out)
}

pub fn mask_apdu_command(
    sequence: u64,
    command: &[u8],
    policy: LogPolicy,
) -> KernelResult<ApduTrace> {
    validate_replay_apdu(command)?;
    let cla = command.first().copied();
    let ins = command.get(1).copied();
    let p1 = command.get(2).copied();
    let p2 = command.get(3).copied();
    let data = if is_pin_verify_with_data(command) {
        MaskedValue::Suppressed("pin-verify-data")
    } else if policy.allows_full_apdu() {
        MaskedValue::Hex(to_hex(apdu_command_data(command)))
    } else {
        MaskedValue::Suppressed("full-apdu-disabled")
    };

    Ok(ApduTrace {
        sequence,
        direction: ApduDirection::Command,
        context: ApduTraceContext::Generic,
        cla,
        ins,
        p1,
        p2,
        sw: None,
        data,
        fields: Vec::new(),
    })
}

pub fn mask_apdu_response(
    sequence: u64,
    context: ApduTraceContext,
    response_data: &[u8],
    sw: [u8; 2],
    policy: LogPolicy,
) -> KernelResult<ApduTrace> {
    validate_replay_apdu(response_data)?;
    let fields = match context {
        ApduTraceContext::Generic => mask_tlv_stream(response_data, policy).unwrap_or_default(),
        ApduTraceContext::GenerateAcResponse => mask_generate_ac_response(response_data, policy)?,
    };
    let data = if fields.is_empty() {
        MaskedValue::Suppressed("unparsed-response")
    } else {
        MaskedValue::Suppressed("tag-masked")
    };

    Ok(ApduTrace {
        sequence,
        direction: ApduDirection::Response,
        context,
        cla: None,
        ins: None,
        p1: None,
        p2: None,
        sw: Some(sw),
        data,
        fields,
    })
}

impl ApduTrace {
    pub fn to_json(&self) -> String {
        let mut out = String::new();
        self.push_json(&mut out);
        out
    }

    fn push_json(&self, out: &mut String) {
        out.push('{');
        push_json_number(out, "sequence", self.sequence);
        out.push(',');
        push_json_str(out, "direction", direction_name(self.direction));
        out.push(',');
        push_json_str(out, "context", context_name(self.context));
        if let Some(cla) = self.cla {
            out.push(',');
            push_json_hex_byte(out, "cla", cla);
        }
        if let Some(ins) = self.ins {
            out.push(',');
            push_json_hex_byte(out, "ins", ins);
        }
        if let Some(p1) = self.p1 {
            out.push(',');
            push_json_hex_byte(out, "p1", p1);
        }
        if let Some(p2) = self.p2 {
            out.push(',');
            push_json_hex_byte(out, "p2", p2);
        }
        if let Some(sw) = self.sw {
            out.push(',');
            push_json_str(out, "sw", &to_hex(&sw));
        }
        out.push(',');
        push_masked_value(out, "data", &self.data);
        out.push_str(",\"fields\":[");
        for (idx, field) in self.fields.iter().enumerate() {
            if idx > 0 {
                out.push(',');
            }
            out.push('{');
            push_json_str(out, "tag", &to_hex(&field.tag));
            out.push(',');
            push_masked_value(out, "value", &field.value);
            out.push('}');
        }
        out.push_str("]}");
    }
}

fn mask_generate_ac_response(
    response_data: &[u8],
    policy: LogPolicy,
) -> KernelResult<Vec<MaskedField>> {
    let response = parse_generate_ac_response(response_data)?;
    let mut fields = Vec::new();
    push_gac_fields(&response, policy, &mut fields);
    Ok(fields)
}

fn push_gac_fields(
    response: &GenerateAcResponse,
    policy: LogPolicy,
    fields: &mut Vec<MaskedField>,
) {
    fields.push(mask_tlv_value(&[0x9f, 0x27], &[response.cid.raw()], policy));
    fields.push(mask_tlv_value(&[0x9f, 0x36], &response.atc, policy));
    fields.push(mask_tlv_value(
        &[0x9f, 0x26],
        &response.application_cryptogram,
        policy,
    ));
    if !response.issuer_application_data.is_empty() {
        fields.push(mask_tlv_value(
            &[0x9f, 0x10],
            &response.issuer_application_data,
            policy,
        ));
    }
    if let Some(dynamic_number) = &response.icc_dynamic_number {
        fields.push(mask_tlv_value(&[0x9f, 0x4c], dynamic_number, policy));
    }
}

fn push_trace_identity_json(out: &mut String, identity: &TraceIdentity, policy: LogPolicy) {
    out.push('{');
    push_json_str(out, "type", "trace-identity");
    out.push(',');
    push_json_str(out, "kernel_name", identity.kernel_name);
    out.push(',');
    push_json_str(out, "kernel_version", identity.kernel_version);
    out.push(',');
    push_json_number(out, "abi_version", identity.abi_version as u64);
    out.push(',');
    push_json_number(out, "profile_version", identity.profile_version);
    out.push(',');
    push_json_str(
        out,
        "log_build_mode",
        log_build_mode_name(policy.build_mode),
    );
    out.push(',');
    push_json_bool(
        out,
        "support_authorization_verified",
        policy.support_verified(),
    );
    out.push('}');
}

fn log_build_mode_name(mode: LogBuildMode) -> &'static str {
    match mode {
        LogBuildMode::Production => "production",
        LogBuildMode::Certification => "certification",
        LogBuildMode::Development => "development",
    }
}

fn validate_replay_apdu(bytes: &[u8]) -> KernelResult<()> {
    if bytes.len() > MAX_REPLAY_APDU_BYTES {
        return Err(KernelError::LengthOverflow);
    }
    Ok(())
}

fn is_pin_verify_with_data(command: &[u8]) -> bool {
    command.get(1) == Some(&0x20) && !apdu_command_data(command).is_empty()
}

fn apdu_command_data(command: &[u8]) -> &[u8] {
    if command.len() <= 5 {
        return &[];
    }
    let lc = command[4] as usize;
    let data_end = 5usize.saturating_add(lc).min(command.len());
    &command[5..data_end]
}

fn mask_pan_bcd(value: &[u8]) -> String {
    let mut digits = Vec::with_capacity(value.len() * 2);
    for byte in value {
        for nibble in [byte >> 4, byte & 0x0f] {
            if nibble <= 9 {
                digits.push((b'0' + nibble) as char);
            }
        }
    }

    let keep = digits.len().min(4);
    let masked_len = digits.len().saturating_sub(keep);
    let mut out = String::with_capacity(digits.len());
    for _ in 0..masked_len {
        out.push('*');
    }
    for digit in digits.iter().skip(masked_len) {
        out.push(*digit);
    }
    out
}

fn fnv1a64(value: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in value {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn direction_name(direction: ApduDirection) -> &'static str {
    match direction {
        ApduDirection::Command => "command",
        ApduDirection::Response => "response",
    }
}

fn context_name(context: ApduTraceContext) -> &'static str {
    match context {
        ApduTraceContext::Generic => "generic",
        ApduTraceContext::GenerateAcResponse => "generate-ac-response",
    }
}

fn push_json_number(out: &mut String, key: &str, value: u64) {
    push_json_key(out, key);
    out.push_str(&value.to_string());
}

fn push_json_hex_byte(out: &mut String, key: &str, value: u8) {
    push_json_str(out, key, &to_hex(&[value]));
}

fn push_json_bool(out: &mut String, key: &str, value: bool) {
    push_json_key(out, key);
    out.push_str(if value { "true" } else { "false" });
}

fn push_json_str(out: &mut String, key: &str, value: &str) {
    push_json_key(out, key);
    push_json_string(out, value);
}

fn push_masked_value(out: &mut String, key: &str, value: &MaskedValue) {
    push_json_key(out, key);
    match value {
        MaskedValue::Hex(hex) => {
            out.push('{');
            push_json_str(out, "type", "hex");
            out.push(',');
            push_json_str(out, "value", hex);
            out.push('}');
        }
        MaskedValue::Pan(masked) => {
            out.push('{');
            push_json_str(out, "type", "pan");
            out.push(',');
            push_json_str(out, "value", masked);
            out.push('}');
        }
        MaskedValue::Suppressed(reason) => {
            out.push('{');
            push_json_str(out, "type", "suppressed");
            out.push(',');
            push_json_str(out, "reason", reason);
            out.push('}');
        }
        MaskedValue::DebugHash { len, hash64 } => {
            out.push('{');
            push_json_str(out, "type", "debug-hash");
            out.push(',');
            push_json_number(out, "len", *len as u64);
            out.push(',');
            push_json_str(out, "hash64", &format!("{hash64:016x}"));
            out.push('}');
        }
    }
}

fn push_json_key(out: &mut String, key: &str) {
    push_json_string(out, key);
    out.push(':');
}

fn push_json_string(out: &mut String, value: &str) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pan_mask_keeps_only_last_four_digits() {
        let field = mask_tlv_value(
            &[0x5a],
            &[0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x5f],
            LogPolicy::production(),
        );
        assert_eq!(field.value, MaskedValue::Pan("***********2345".to_string()));
    }

    #[test]
    fn track2_never_logs_raw_value() {
        let raw = [
            0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0xd2, 0x51, 0x22, 0x01, 0x23, 0x45, 0x67, 0x8f,
        ];
        let production = mask_tlv_value(&[0x57], &raw, LogPolicy::production());
        assert_eq!(production.value, MaskedValue::Suppressed("track2"));

        let support = mask_tlv_value(&[0x57], &raw, LogPolicy::certification_support());
        assert!(matches!(
            support.value,
            MaskedValue::DebugHash { len: 14, .. }
        ));
    }

    #[test]
    fn production_suppresses_transaction_cryptograms() {
        let field = mask_tlv_value(
            &[0x9f, 0x26],
            &[0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x01],
            LogPolicy::production(),
        );
        assert_eq!(
            field.value,
            MaskedValue::Suppressed("transaction-cryptogram")
        );
    }

    #[test]
    fn generate_ac_response_trace_masks_format_80_cryptogram() {
        let response = [
            0x80, 0x0b, 0x80, 0x00, 0x01, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x01,
        ];
        let event = mask_apdu_response(
            7,
            ApduTraceContext::GenerateAcResponse,
            &response,
            [0x90, 0x00],
            LogPolicy::production(),
        )
        .unwrap();
        let json = event.to_json();
        assert!(json.contains("\"tag\":\"9f26\""));
        assert!(json.contains("transaction-cryptogram"));
        assert!(!json.contains("deadbeef00000001"));
    }

    #[test]
    fn production_policy_never_emits_full_apdu_data_even_if_misconfigured() {
        let misconfigured = LogPolicy {
            build_mode: LogBuildMode::Production,
            support_authorization: SupportAuthorization::Verified,
            full_apdu: true,
            track2_debug_hash: true,
            transaction_cryptograms: true,
        };
        let command = [
            0x80, 0xa8, 0x00, 0x00, 0x06, 0x83, 0x04, 0x01, 0x02, 0x03, 0x04, 0x00,
        ];
        let event = mask_apdu_command(1, &command, misconfigured).unwrap();

        assert_eq!(event.data, MaskedValue::Suppressed("full-apdu-disabled"));
        assert!(!event.to_json().contains("830401020304"));
    }

    #[test]
    fn apdu_trace_debug_redacts_masked_payloads_for_crash_safety() {
        let event = mask_apdu_command(
            1,
            &[0x80, 0xca, 0x00, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef],
            LogPolicy::certification_support(),
        )
        .unwrap();
        assert!(matches!(event.data, MaskedValue::Hex(_)));
        assert!(event.to_json().contains("deadbeef"));

        let field = mask_tlv_value(
            &[0x9f, 0x10],
            &[0xde, 0xad, 0xbe, 0xef],
            LogPolicy::certification_support(),
        );
        let value = MaskedValue::Hex("deadbeef".to_string());

        for debug in [
            format!("{:?}", event),
            format!("{:?}", field),
            format!("{:?}", value),
        ] {
            assert!(debug.contains("redacted for crash safety"));
            assert!(!debug.contains("deadbeef"));
        }
    }

    #[test]
    fn replay_is_exact_order_and_evidence_is_masked() {
        let select = ReplayExchange::new(
            &[
                0x00, 0xa4, 0x04, 0x00, 0x07, 0xa0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10, 0x00,
            ],
            &[
                0x6f, 0x09, 0x84, 0x07, 0xa0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10,
            ],
            [0x90, 0x00],
            ApduTraceContext::Generic,
        )
        .unwrap();
        let record = ReplayExchange::new(
            &[0x00, 0xb2, 0x01, 0x14, 0x00],
            &[
                0x70, 0x0a, 0x5a, 0x08, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x5f,
            ],
            [0x90, 0x00],
            ApduTraceContext::Generic,
        )
        .unwrap();
        let mut script = ReplayScript::new(vec![select, record]).unwrap();
        assert!(script.exchange(&[0x00, 0xb2, 0x01, 0x14, 0x00]).is_err());
        let _ = script
            .exchange(&[
                0x00, 0xa4, 0x04, 0x00, 0x07, 0xa0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10, 0x00,
            ])
            .unwrap();
        let _ = script.exchange(&[0x00, 0xb2, 0x01, 0x14, 0x00]).unwrap();
        assert_eq!(script.remaining(), 0);

        let jsonl = script.masked_jsonl(LogPolicy::production()).unwrap();
        assert!(jsonl.contains("***********2345"));
        assert!(!jsonl.contains("123456789012345"));
    }

    #[test]
    fn replay_debug_redacts_raw_apdu_bytes_for_crash_safety() {
        let record = ReplayExchange::new(
            &[0x00, 0xb2, 0x01, 0x14, 0x00],
            &[
                0x70, 0x0a, 0x5a, 0x08, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x5f,
            ],
            [0x90, 0x00],
            ApduTraceContext::Generic,
        )
        .unwrap();
        let exchange_debug = format!("{record:?}");
        assert!(exchange_debug.contains("raw APDU bytes redacted"));
        assert!(!exchange_debug.contains("123456789012345"));
        assert!(!exchange_debug.contains("5a"));

        let script = ReplayScript::new(vec![record]).unwrap();
        let script_debug = format!("{script:?}");
        assert!(script_debug.contains("raw APDU bytes redacted"));
        assert!(!script_debug.contains("123456789012345"));
        assert!(!script_debug.contains("5a"));
    }

    #[test]
    fn replay_trace_identity_records_profile_version_without_unmasking_data() {
        let record = ReplayExchange::new(
            &[0x00, 0xb2, 0x01, 0x14, 0x00],
            &[
                0x70, 0x0a, 0x5a, 0x08, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x5f,
            ],
            [0x90, 0x00],
            ApduTraceContext::Generic,
        )
        .unwrap();
        let script = ReplayScript::new(vec![record]).unwrap();
        let identity = TraceIdentity::current(1, 42);

        let jsonl = script
            .masked_jsonl_with_trace_identity(LogPolicy::production(), &identity)
            .unwrap();

        assert!(jsonl.starts_with("{\"type\":\"trace-identity\""));
        assert!(jsonl.contains("\"kernel_name\":\"hyperion-emv\""));
        assert!(jsonl.contains("\"abi_version\":1"));
        assert!(jsonl.contains("\"profile_version\":42"));
        assert!(jsonl.contains("\"log_build_mode\":\"production\""));
        assert!(jsonl.contains("\"support_authorization_verified\":false"));
        assert!(jsonl.contains("***********2345"));
        assert!(!jsonl.contains("123456789012345"));
    }

    #[test]
    fn replay_rejects_pin_verify_payload_custody() {
        let err = ReplayExchange::new(
            &[
                0x00, 0x20, 0x00, 0x80, 0x08, 0x24, 0x12, 0x34, 0xff, 0xff, 0xff, 0xff, 0xff,
            ],
            &[],
            [0x90, 0x00],
            ApduTraceContext::Generic,
        )
        .unwrap_err();
        assert_eq!(err, KernelError::InvalidArgument);
    }
}
