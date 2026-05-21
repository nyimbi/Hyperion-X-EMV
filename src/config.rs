use crate::error::{KernelError, KernelResult};
use crate::restrictions::EmvDate;
use crate::taa::{ActionCodes, TaaProfile, TerminalAction};
use crate::trm::TrmProfile;
use std::collections::BTreeMap;

pub const MAX_JSON_DEPTH: usize = 24;
pub const MAX_JSON_NODES: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuildMode {
    Test,
    Certification,
    Production,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureStatus {
    NotPresent,
    Invalid,
    Verified,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigLoadPolicy {
    pub mode: BuildMode,
    pub signature_status: SignatureStatus,
    pub installed_version: u64,
    pub candidate_version: u64,
    pub evaluation_date: EmvDate,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileSet {
    pub version: u64,
    pub schemes: Vec<SchemeProfile>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SchemeProfile {
    pub scheme_name: String,
    pub rid: [u8; 5],
    pub kernel_type: String,
    pub taa: TaaProfile,
    pub aids: Vec<AidProfile>,
    pub capks: Vec<Capk>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AidProfile {
    pub aid: Vec<u8>,
    pub priority: u8,
    pub partial_selection: bool,
    pub interfaces: Vec<String>,
    pub action_codes: ActionCodes,
    pub floor_limit: u64,
    pub cvm_limit_contact: u64,
    pub random_selection_percent: u8,
    pub contactless_transaction_limit: u64,
    pub contactless_cvm_limit: u64,
    pub cdcvm_supported: bool,
    pub cda_supported: bool,
    pub cda_request_encoding: Option<String>,
    pub critical_issuer_script_ins: Vec<u8>,
}

impl AidProfile {
    pub fn trm_profile(&self) -> Option<TrmProfile> {
        TrmProfile::new(self.floor_limit, self.random_selection_percent, None, None)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Capk {
    pub rid: [u8; 5],
    pub key_index: u8,
    pub modulus: Vec<u8>,
    pub exponent: Vec<u8>,
    pub expiry: EmvDate,
    pub checksum: Vec<u8>,
}

pub fn load_profile_set(json: &[u8], policy: &ConfigLoadPolicy) -> KernelResult<ProfileSet> {
    if matches!(
        policy.mode,
        BuildMode::Certification | BuildMode::Production
    ) && policy.signature_status != SignatureStatus::Verified
    {
        return Err(KernelError::InvalidProfile);
    }
    if policy.candidate_version < policy.installed_version {
        return Err(KernelError::InvalidProfile);
    }

    let root = JsonParser::new(json).parse()?;
    let object = root.as_object()?;
    let schemes_value = object
        .get("scheme_profiles")
        .ok_or(KernelError::InvalidProfile)?;
    let schemes_array = schemes_value.as_array()?;
    if schemes_array.is_empty() {
        return Err(KernelError::InvalidProfile);
    }

    let mut schemes = Vec::with_capacity(schemes_array.len());
    for scheme_value in schemes_array {
        schemes.push(parse_scheme(scheme_value, policy.evaluation_date)?);
    }
    Ok(ProfileSet {
        version: policy.candidate_version,
        schemes,
    })
}

fn parse_scheme(value: &JsonValue, evaluation_date: EmvDate) -> KernelResult<SchemeProfile> {
    let object = value.as_object()?;
    let scheme_name = required_string(object, "scheme_name")?;
    reject_placeholder(scheme_name)?;
    let rid_vec = parse_hex_field(object, "rid")?;
    let rid = fixed_vec::<5>(rid_vec)?;
    reject_dummy_bytes(&rid)?;
    let kernel_type = required_string(object, "kernel_type")?.to_string();

    let taa = TaaProfile::new(
        parse_action(required_string(
            object,
            "taa_fallback_when_offline_unable_online",
        )?)?,
        parse_action(required_string(
            object,
            "taa_no_match_default_when_online_capable",
        )?)?,
        parse_action(required_string(
            object,
            "taa_no_match_default_when_offline_only",
        )?)?,
    )?;

    let aids_value = object.get("aids").ok_or(KernelError::InvalidProfile)?;
    let aids_array = aids_value.as_array()?;
    if aids_array.is_empty() {
        return Err(KernelError::InvalidProfile);
    }
    let mut aids = Vec::with_capacity(aids_array.len());
    for aid_value in aids_array {
        aids.push(parse_aid(aid_value)?);
    }

    let capks_value = object.get("capks").ok_or(KernelError::InvalidProfile)?;
    let capks_array = capks_value.as_array()?;
    if capks_array.is_empty() {
        return Err(KernelError::InvalidProfile);
    }
    let mut capks = Vec::with_capacity(capks_array.len());
    for capk_value in capks_array {
        capks.push(parse_capk(capk_value, rid, evaluation_date)?);
    }

    Ok(SchemeProfile {
        scheme_name: scheme_name.to_string(),
        rid,
        kernel_type,
        taa,
        aids,
        capks,
    })
}

fn parse_aid(value: &JsonValue) -> KernelResult<AidProfile> {
    let object = value.as_object()?;
    let aid = parse_hex_field(object, "aid")?;
    if !(5..=16).contains(&aid.len()) {
        return Err(KernelError::InvalidProfile);
    }
    reject_dummy_bytes(&aid)?;

    let priority = required_u64(object, "priority")?;
    if priority > u8::MAX as u64 {
        return Err(KernelError::InvalidProfile);
    }

    let interfaces = object
        .get("interfaces")
        .ok_or(KernelError::InvalidProfile)?
        .as_array()?
        .iter()
        .map(|item| item.as_string().map(str::to_string))
        .collect::<KernelResult<Vec<_>>>()?;
    if interfaces.is_empty()
        || interfaces
            .iter()
            .any(|item| item != "contact" && item != "contactless")
    {
        return Err(KernelError::InvalidProfile);
    }

    let random_selection_percent = required_u64(object, "random_selection_percent")?;
    if random_selection_percent > 100 {
        return Err(KernelError::InvalidProfile);
    }

    Ok(AidProfile {
        aid,
        priority: priority as u8,
        partial_selection: required_bool(object, "partial_selection")?,
        interfaces,
        action_codes: ActionCodes {
            online: fixed_vec::<5>(parse_hex_field(object, "tac_online")?)?,
            denial: fixed_vec::<5>(parse_hex_field(object, "tac_denial")?)?,
            default: fixed_vec::<5>(parse_hex_field(object, "tac_default")?)?,
        },
        floor_limit: required_u64(object, "floor_limit")?,
        cvm_limit_contact: required_u64(object, "cvm_limit_contact")?,
        random_selection_percent: random_selection_percent as u8,
        contactless_transaction_limit: required_u64(object, "contactless_transaction_limit")?,
        contactless_cvm_limit: required_u64(object, "contactless_cvm_limit")?,
        cdcvm_supported: required_bool(object, "cdcvm_supported")?,
        cda_supported: required_bool(object, "cda_supported")?,
        cda_request_encoding: object
            .get("cda_request_encoding")
            .and_then(JsonValue::as_string_opt)
            .map(str::to_string),
        critical_issuer_script_ins: optional_hex_byte_array(object, "critical_issuer_script_ins")?,
    })
}

fn parse_capk(value: &JsonValue, rid: [u8; 5], evaluation_date: EmvDate) -> KernelResult<Capk> {
    let object = value.as_object()?;
    let key_index = required_u64(object, "key_index")?;
    if key_index > u8::MAX as u64 {
        return Err(KernelError::InvalidProfile);
    }
    let modulus = parse_hex_field(object, "modulus_hex")?;
    let exponent = parse_hex_field(object, "exponent_hex")?;
    let checksum = parse_hex_field(object, "checksum_hex")?;
    if modulus.len() < 64 || exponent.is_empty() || checksum.len() < 16 {
        return Err(KernelError::InvalidProfile);
    }
    reject_dummy_bytes(&modulus)?;
    reject_dummy_bytes(&checksum)?;

    let expiry = parse_iso_date(required_string(object, "expiry")?)?;
    if expiry < evaluation_date {
        return Err(KernelError::InvalidProfile);
    }

    Ok(Capk {
        rid,
        key_index: key_index as u8,
        modulus,
        exponent,
        expiry,
        checksum,
    })
}

fn parse_action(input: &str) -> KernelResult<TerminalAction> {
    match input {
        "AAC" => Ok(TerminalAction::Aac),
        "TC" => Ok(TerminalAction::Tc),
        "ARQC" => Ok(TerminalAction::Arqc),
        _ => Err(KernelError::InvalidProfile),
    }
}

fn parse_iso_date(input: &str) -> KernelResult<EmvDate> {
    let bytes = input.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return Err(KernelError::ParseError);
    }
    let year = decimal_pair(bytes[2], bytes[3])?;
    let month = decimal_pair(bytes[5], bytes[6])?;
    let day = decimal_pair(bytes[8], bytes[9])?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return Err(KernelError::ParseError);
    }
    Ok(EmvDate { year, month, day })
}

fn decimal_pair(high: u8, low: u8) -> KernelResult<u8> {
    if !high.is_ascii_digit() || !low.is_ascii_digit() {
        return Err(KernelError::ParseError);
    }
    Ok((high - b'0') * 10 + low - b'0')
}

fn required_string<'a>(
    object: &'a BTreeMap<String, JsonValue>,
    key: &str,
) -> KernelResult<&'a str> {
    object
        .get(key)
        .ok_or(KernelError::InvalidProfile)?
        .as_string()
}

fn required_u64(object: &BTreeMap<String, JsonValue>, key: &str) -> KernelResult<u64> {
    object.get(key).ok_or(KernelError::InvalidProfile)?.as_u64()
}

fn required_bool(object: &BTreeMap<String, JsonValue>, key: &str) -> KernelResult<bool> {
    object
        .get(key)
        .ok_or(KernelError::InvalidProfile)?
        .as_bool()
}

fn parse_hex_field(object: &BTreeMap<String, JsonValue>, key: &str) -> KernelResult<Vec<u8>> {
    let value = required_string(object, key)?;
    reject_placeholder(value)?;
    decode_hex(value)
}

fn optional_hex_byte_array(
    object: &BTreeMap<String, JsonValue>,
    key: &str,
) -> KernelResult<Vec<u8>> {
    let Some(value) = object.get(key) else {
        return Ok(Vec::new());
    };
    value
        .as_array()?
        .iter()
        .map(|item| {
            let bytes = decode_hex(item.as_string()?)?;
            if bytes.len() == 1 {
                Ok(bytes[0])
            } else {
                Err(KernelError::InvalidProfile)
            }
        })
        .collect()
}

pub fn decode_hex(input: &str) -> KernelResult<Vec<u8>> {
    let bytes = input.as_bytes();
    if bytes.is_empty() || bytes.len() % 2 != 0 {
        return Err(KernelError::ParseError);
    }
    bytes
        .chunks_exact(2)
        .map(|pair| Ok((hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?))
        .collect()
}

fn hex_nibble(byte: u8) -> KernelResult<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(KernelError::ParseError),
    }
}

fn reject_placeholder(value: &str) -> KernelResult<()> {
    let upper = value.to_ascii_uppercase();
    if upper.contains("...")
        || upper.contains("PLACEHOLDER")
        || upper.contains("EXAMPLE_NOT")
        || upper.contains("DUMMY")
        || upper.contains("TEST_ONLY")
    {
        return Err(KernelError::InvalidProfile);
    }
    Ok(())
}

fn reject_dummy_bytes(value: &[u8]) -> KernelResult<()> {
    if value.iter().all(|byte| *byte == 0) || value.iter().all(|byte| *byte == 0xff) {
        return Err(KernelError::InvalidProfile);
    }
    Ok(())
}

fn fixed_vec<const N: usize>(value: Vec<u8>) -> KernelResult<[u8; N]> {
    if value.len() != N {
        return Err(KernelError::InvalidProfile);
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&value);
    Ok(out)
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum JsonValue {
    Object(BTreeMap<String, JsonValue>),
    Array(Vec<JsonValue>),
    String(String),
    Number(u64),
    Bool(bool),
    Null,
}

impl JsonValue {
    fn as_object(&self) -> KernelResult<&BTreeMap<String, JsonValue>> {
        match self {
            Self::Object(object) => Ok(object),
            _ => Err(KernelError::ParseError),
        }
    }

    fn as_array(&self) -> KernelResult<&[JsonValue]> {
        match self {
            Self::Array(array) => Ok(array),
            _ => Err(KernelError::ParseError),
        }
    }

    fn as_string(&self) -> KernelResult<&str> {
        match self {
            Self::String(value) => Ok(value),
            _ => Err(KernelError::ParseError),
        }
    }

    fn as_string_opt(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            _ => None,
        }
    }

    fn as_u64(&self) -> KernelResult<u64> {
        match self {
            Self::Number(value) => Ok(*value),
            _ => Err(KernelError::ParseError),
        }
    }

    fn as_bool(&self) -> KernelResult<bool> {
        match self {
            Self::Bool(value) => Ok(*value),
            _ => Err(KernelError::ParseError),
        }
    }
}

struct JsonParser<'a> {
    input: &'a [u8],
    offset: usize,
    nodes: usize,
}

impl<'a> JsonParser<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            offset: 0,
            nodes: 0,
        }
    }

    fn parse(mut self) -> KernelResult<JsonValue> {
        let value = self.parse_value(0)?;
        self.skip_ws();
        if self.offset != self.input.len() {
            return Err(KernelError::ParseError);
        }
        Ok(value)
    }

    fn parse_value(&mut self, depth: usize) -> KernelResult<JsonValue> {
        if depth > MAX_JSON_DEPTH || self.nodes >= MAX_JSON_NODES {
            return Err(KernelError::LengthOverflow);
        }
        self.nodes += 1;
        self.skip_ws();
        match self.peek().ok_or(KernelError::ParseError)? {
            b'{' => self.parse_object(depth + 1),
            b'[' => self.parse_array(depth + 1),
            b'"' => self.parse_string().map(JsonValue::String),
            b't' => {
                self.expect_literal(b"true")?;
                Ok(JsonValue::Bool(true))
            }
            b'f' => {
                self.expect_literal(b"false")?;
                Ok(JsonValue::Bool(false))
            }
            b'n' => {
                self.expect_literal(b"null")?;
                Ok(JsonValue::Null)
            }
            b'0'..=b'9' => self.parse_number().map(JsonValue::Number),
            _ => Err(KernelError::ParseError),
        }
    }

    fn parse_object(&mut self, depth: usize) -> KernelResult<JsonValue> {
        self.expect_byte(b'{')?;
        self.skip_ws();
        let mut object = BTreeMap::new();
        if self.consume_if(b'}') {
            return Ok(JsonValue::Object(object));
        }
        loop {
            self.skip_ws();
            let key = self.parse_string()?;
            self.skip_ws();
            self.expect_byte(b':')?;
            let value = self.parse_value(depth)?;
            if object.insert(key, value).is_some() {
                return Err(KernelError::InvalidProfile);
            }
            self.skip_ws();
            if self.consume_if(b'}') {
                break;
            }
            self.expect_byte(b',')?;
        }
        Ok(JsonValue::Object(object))
    }

    fn parse_array(&mut self, depth: usize) -> KernelResult<JsonValue> {
        self.expect_byte(b'[')?;
        self.skip_ws();
        let mut array = Vec::new();
        if self.consume_if(b']') {
            return Ok(JsonValue::Array(array));
        }
        loop {
            array.push(self.parse_value(depth)?);
            self.skip_ws();
            if self.consume_if(b']') {
                break;
            }
            self.expect_byte(b',')?;
        }
        Ok(JsonValue::Array(array))
    }

    fn parse_string(&mut self) -> KernelResult<String> {
        self.expect_byte(b'"')?;
        let mut out = String::new();
        while let Some(byte) = self.next() {
            match byte {
                b'"' => return Ok(out),
                b'\\' => {
                    let escaped = self.next().ok_or(KernelError::ParseError)?;
                    match escaped {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        _ => return Err(KernelError::ParseError),
                    }
                }
                0x00..=0x1f => return Err(KernelError::ParseError),
                _ => out.push(byte as char),
            }
        }
        Err(KernelError::ParseError)
    }

    fn parse_number(&mut self) -> KernelResult<u64> {
        let start = self.offset;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.offset += 1;
        }
        let digits = std::str::from_utf8(&self.input[start..self.offset])
            .map_err(|_| KernelError::ParseError)?;
        digits.parse().map_err(|_| KernelError::ParseError)
    }

    fn expect_literal(&mut self, literal: &[u8]) -> KernelResult<()> {
        if self.input.get(self.offset..self.offset + literal.len()) == Some(literal) {
            self.offset += literal.len();
            Ok(())
        } else {
            Err(KernelError::ParseError)
        }
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.offset += 1;
        }
    }

    fn expect_byte(&mut self, expected: u8) -> KernelResult<()> {
        if self.next() == Some(expected) {
            Ok(())
        } else {
            Err(KernelError::ParseError)
        }
    }

    fn consume_if(&mut self, expected: u8) -> bool {
        if self.peek() == Some(expected) {
            self.offset += 1;
            true
        } else {
            false
        }
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.offset).copied()
    }

    fn next(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.offset += 1;
        Some(byte)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_PROFILE: &[u8] = br#"{
      "scheme_profiles": [{
        "scheme_name": "Visa",
        "rid": "A000000003",
        "kernel_type": "c8_contactless",
        "taa_fallback_when_offline_unable_online": "AAC",
        "taa_no_match_default_when_online_capable": "ARQC",
        "taa_no_match_default_when_offline_only": "AAC",
        "aids": [{
          "aid": "A0000000031010",
          "priority": 10,
          "partial_selection": true,
          "interfaces": ["contact", "contactless"],
          "tac_online": "E0F8C80000",
          "tac_denial": "0000000000",
          "tac_default": "8000000000",
          "iac_online": "0000000000",
          "iac_denial": "0000000000",
          "iac_default": "0000000000",
          "floor_limit": 0,
          "cvm_limit_contact": 5000,
          "random_selection_percent": 5,
          "contactless_transaction_limit": 5000,
          "contactless_cvm_limit": 3000,
          "cdcvm_supported": true,
          "cda_supported": true,
          "cda_request_encoding": "CDOL1_bit",
          "critical_issuer_script_ins": ["E2"]
        }],
        "capks": [{
          "key_index": 1,
          "modulus_hex": "D2E5F5B3A1C8D4E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B9C0",
          "exponent_hex": "010001",
          "expiry": "2030-12-31",
          "checksum_hex": "A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6"
        }]
      }]
    }"#;

    fn policy(signature_status: SignatureStatus) -> ConfigLoadPolicy {
        ConfigLoadPolicy {
            mode: BuildMode::Certification,
            signature_status,
            installed_version: 1,
            candidate_version: 2,
            evaluation_date: EmvDate {
                year: 26,
                month: 5,
                day: 21,
            },
        }
    }

    #[test]
    fn loads_profile_annex_when_signature_is_verified() {
        let profiles = load_profile_set(VALID_PROFILE, &policy(SignatureStatus::Verified)).unwrap();

        assert_eq!(profiles.schemes.len(), 1);
        assert_eq!(profiles.schemes[0].rid, [0xa0, 0x00, 0x00, 0x00, 0x03]);
        assert_eq!(
            profiles.schemes[0].aids[0].action_codes.online,
            [0xe0, 0xf8, 0xc8, 0, 0]
        );
        assert_eq!(profiles.schemes[0].capks[0].key_index, 1);
        assert!(profiles.schemes[0].capks[0].modulus.len() >= 64);
        assert_eq!(
            profiles.schemes[0].aids[0].critical_issuer_script_ins,
            [0xe2]
        );
    }

    #[test]
    fn rejects_unsigned_certification_profile_and_rollback() {
        assert_eq!(
            load_profile_set(VALID_PROFILE, &policy(SignatureStatus::NotPresent)).unwrap_err(),
            KernelError::InvalidProfile
        );

        let rollback = ConfigLoadPolicy {
            candidate_version: 1,
            installed_version: 2,
            ..policy(SignatureStatus::Verified)
        };
        assert_eq!(
            load_profile_set(VALID_PROFILE, &rollback).unwrap_err(),
            KernelError::InvalidProfile
        );
    }

    #[test]
    fn rejects_placeholder_and_bad_hex_material() {
        let placeholder = br#"{"scheme_profiles":[{"scheme_name":"Dummy","rid":"A000000003","kernel_type":"x","taa_fallback_when_offline_unable_online":"AAC","taa_no_match_default_when_online_capable":"ARQC","taa_no_match_default_when_offline_only":"AAC","aids":[{"aid":"A0000000031010","priority":1,"partial_selection":true,"interfaces":["contact"],"tac_online":"0000000000","tac_denial":"0000000000","tac_default":"0000000000","iac_online":"0000000000","iac_denial":"0000000000","iac_default":"0000000000","floor_limit":0,"cvm_limit_contact":0,"random_selection_percent":0,"contactless_transaction_limit":0,"contactless_cvm_limit":0,"cdcvm_supported":false,"cda_supported":false}],"capks":[{"key_index":1,"modulus_hex":"EXAMPLE_NOT_A_REAL_KEY","exponent_hex":"010001","expiry":"2030-01-01","checksum_hex":"00112233445566778899AABBCCDDEEFF"}]}]}"#;
        assert_eq!(
            load_profile_set(placeholder, &policy(SignatureStatus::Verified)).unwrap_err(),
            KernelError::InvalidProfile
        );
        assert_eq!(decode_hex("A00Z").unwrap_err(), KernelError::ParseError);
    }

    #[test]
    fn rejects_expired_capk() {
        let expired = ConfigLoadPolicy {
            evaluation_date: EmvDate {
                year: 31,
                month: 1,
                day: 2,
            },
            ..policy(SignatureStatus::Verified)
        };
        assert_eq!(
            load_profile_set(VALID_PROFILE, &expired).unwrap_err(),
            KernelError::InvalidProfile
        );
    }

    #[test]
    fn rejects_invalid_critical_script_ins_policy() {
        let invalid = br#"{
          "scheme_profiles": [{
            "scheme_name": "Visa",
            "rid": "A000000003",
            "kernel_type": "c8_contactless",
            "taa_fallback_when_offline_unable_online": "AAC",
            "taa_no_match_default_when_online_capable": "ARQC",
            "taa_no_match_default_when_offline_only": "AAC",
            "aids": [{
              "aid": "A0000000031010",
              "priority": 10,
              "partial_selection": true,
              "interfaces": ["contact", "contactless"],
              "tac_online": "E0F8C80000",
              "tac_denial": "0000000000",
              "tac_default": "8000000000",
              "iac_online": "0000000000",
              "iac_denial": "0000000000",
              "iac_default": "0000000000",
              "floor_limit": 0,
              "cvm_limit_contact": 5000,
              "random_selection_percent": 5,
              "contactless_transaction_limit": 5000,
              "contactless_cvm_limit": 3000,
              "cdcvm_supported": true,
              "cda_supported": true,
              "critical_issuer_script_ins": ["E200"]
            }],
            "capks": [{
              "key_index": 1,
              "modulus_hex": "D2E5F5B3A1C8D4E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B9C0",
              "exponent_hex": "010001",
              "expiry": "2030-12-31",
              "checksum_hex": "A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6"
            }]
          }]
        }"#;
        assert_eq!(
            load_profile_set(invalid, &policy(SignatureStatus::Verified)).unwrap_err(),
            KernelError::InvalidProfile
        );
    }
}
