use crate::config::{decode_hex, Capk, ProfileSet};
use crate::error::{KernelError, KernelResult};
use crate::restrictions::EmvDate;
use crate::state::{Tsi, Tvr};
use crate::tlv;

pub const MIN_ODA_CERTIFICATE_BYTES: usize = 16;
pub const MIN_ODA_SIGNATURE_BYTES: usize = 8;
const SHA1_DIGEST_BYTES: usize = 20;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OdaMethod {
    Sda,
    Dda,
    Cda,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OdaSelectionInput {
    pub aip_sda_supported: bool,
    pub aip_dda_supported: bool,
    pub aip_cda_supported: bool,
    pub profile_sda_allowed: bool,
    pub profile_dda_allowed: bool,
    pub profile_cda_allowed: bool,
    pub terminal_supports_dynamic_authentication: bool,
    pub oda_required: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OdaSelection {
    NotRequired,
    NotPerformedRequired,
    Perform(OdaMethod),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OdaFailure {
    MissingCapk,
    IssuerCertificateRecovery,
    IccCertificateRecovery,
    StaticSignature,
    DynamicSignature,
    CdaSignature,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OdaOutcome {
    NotPerformed,
    Passed(OdaMethod),
    Failed {
        method: OdaMethod,
        failure: OdaFailure,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapkIntegrity {
    Unverified,
    Verified,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InternalAuthenticateResponse {
    pub signed_dynamic_application_data: Vec<u8>,
    pub icc_dynamic_number: Option<Vec<u8>>,
}

pub fn selection_input_from_aip(
    aip: [u8; 2],
    profile_cda_allowed: bool,
    terminal_supports_dynamic_authentication: bool,
) -> OdaSelectionInput {
    let aip_sda_supported = aip[0] & 0x80 != 0;
    let aip_dda_supported = aip[0] & 0x40 != 0;
    let aip_cda_supported = aip[1] & 0x80 != 0;
    OdaSelectionInput {
        aip_sda_supported,
        aip_dda_supported,
        aip_cda_supported,
        profile_sda_allowed: true,
        profile_dda_allowed: true,
        profile_cda_allowed,
        terminal_supports_dynamic_authentication,
        oda_required: aip_sda_supported || aip_dda_supported || aip_cda_supported,
    }
}

pub fn select_oda_method(input: OdaSelectionInput) -> OdaSelection {
    if input.aip_cda_supported
        && input.profile_cda_allowed
        && input.terminal_supports_dynamic_authentication
    {
        return OdaSelection::Perform(OdaMethod::Cda);
    }
    if input.aip_dda_supported
        && input.profile_dda_allowed
        && input.terminal_supports_dynamic_authentication
    {
        return OdaSelection::Perform(OdaMethod::Dda);
    }
    if input.aip_sda_supported && input.profile_sda_allowed {
        return OdaSelection::Perform(OdaMethod::Sda);
    }
    if input.oda_required {
        OdaSelection::NotPerformedRequired
    } else {
        OdaSelection::NotRequired
    }
}

pub fn select_capk<'a>(
    profiles: &'a ProfileSet,
    rid: &[u8; 5],
    key_index: u8,
    evaluation_date: EmvDate,
    integrity: CapkIntegrity,
) -> KernelResult<&'a Capk> {
    if integrity != CapkIntegrity::Verified {
        return Err(KernelError::InvalidProfile);
    }
    let capk = profiles
        .schemes
        .iter()
        .find(|scheme| &scheme.rid == rid)
        .and_then(|scheme| {
            scheme
                .capks
                .iter()
                .find(|capk| capk.key_index == key_index && capk.expiry >= evaluation_date)
        })
        .ok_or(KernelError::MissingMandatoryTag)?;
    if !capk_checksum_is_valid(capk) {
        return Err(KernelError::MissingMandatoryTag);
    }
    Ok(capk)
}

pub fn capk_checksum_is_valid(capk: &Capk) -> bool {
    if capk.checksum.len() != SHA1_DIGEST_BYTES {
        return false;
    }
    capk.checksum == capk_checksum(capk)
}

pub fn capk_checksum(capk: &Capk) -> [u8; SHA1_DIGEST_BYTES] {
    let mut sha1 = Sha1::new();
    sha1.update(&capk.rid);
    sha1.update(&[capk.key_index]);
    sha1.update(&capk.modulus);
    sha1.update(&capk.exponent);
    sha1.finalize()
}

pub fn apply_oda_outcome(mut tvr: Tvr, mut tsi: Tsi, outcome: OdaOutcome) -> (Tvr, Tsi) {
    match outcome {
        OdaOutcome::NotPerformed => {
            tvr.set(Tvr::B1_OFFLINE_DATA_AUTH_NOT_PERFORMED);
        }
        OdaOutcome::Passed(_) => {
            tsi.set(Tsi::OFFLINE_DATA_AUTHENTICATION_PERFORMED);
        }
        OdaOutcome::Failed { method, failure } => {
            tsi.set(Tsi::OFFLINE_DATA_AUTHENTICATION_PERFORMED);
            if matches!(
                failure,
                OdaFailure::IssuerCertificateRecovery | OdaFailure::IccCertificateRecovery
            ) {
                tvr.set(Tvr::B1_ICC_DATA_MISSING);
            }
            match method {
                OdaMethod::Sda => tvr.set(Tvr::B1_SDA_FAILED),
                OdaMethod::Dda => tvr.set(Tvr::B1_DDA_FAILED),
                OdaMethod::Cda => tvr.set(Tvr::B1_CDA_FAILED),
            }
        }
    }
    (tvr, tsi)
}

pub fn parse_internal_authenticate_response(
    input: &[u8],
) -> KernelResult<InternalAuthenticateResponse> {
    let tlvs = tlv::parse_many(input)?;
    let signed_dynamic_application_data =
        tlv::find_first(&tlvs, &[0x9f, 0x4b]).ok_or(KernelError::MissingMandatoryTag)?;
    if signed_dynamic_application_data.len() < MIN_ODA_SIGNATURE_BYTES {
        return Err(KernelError::InvalidProfile);
    }
    let icc_dynamic_number = tlv::find_first(&tlvs, &[0x9f, 0x4c]).map(|value| value.to_vec());

    Ok(InternalAuthenticateResponse {
        signed_dynamic_application_data: signed_dynamic_application_data.to_vec(),
        icc_dynamic_number,
    })
}

pub fn validate_oda_vector_annex(json: &[u8], certification: bool) -> KernelResult<()> {
    let text = core::str::from_utf8(json).map_err(|_| KernelError::ParseError)?;
    if certification && contains_forbidden_placeholder(text) {
        return Err(KernelError::InvalidProfile);
    }
    for required in [
        "\"test_vectors\"",
        "\"expected_tvr\"",
        "\"expected_oda_result\"",
    ] {
        if !text.contains(required) {
            return Err(KernelError::InvalidProfile);
        }
    }

    let mut hex_fields = 0usize;
    let mut search_from = 0usize;
    while let Some(relative) = text[search_from..].find("_hex\"") {
        let key_end = search_from + relative + 5;
        let key_close = key_end - 1;
        let key_start = text[..key_close]
            .rfind('"')
            .ok_or(KernelError::ParseError)?;
        let key = &text[key_start + 1..key_close];
        let value_start = quoted_value_start(&text[key_end..])
            .map(|offset| key_end + offset)
            .ok_or(KernelError::ParseError)?;
        let value_end = text[value_start..]
            .find('"')
            .map(|offset| value_start + offset)
            .ok_or(KernelError::ParseError)?;
        let value = &text[value_start..value_end];
        validate_vector_hex_field(key, value)?;
        hex_fields += 1;
        search_from = value_end + 1;
    }

    if hex_fields == 0 {
        return Err(KernelError::InvalidProfile);
    }
    Ok(())
}

fn validate_vector_hex_field(key: &str, value: &str) -> KernelResult<()> {
    let bytes = decode_hex(value)?;
    if key.contains("certificate") && bytes.len() < MIN_ODA_CERTIFICATE_BYTES {
        return Err(KernelError::InvalidProfile);
    }
    if (key.contains("signature") || key.contains("response"))
        && bytes.len() < MIN_ODA_SIGNATURE_BYTES
    {
        return Err(KernelError::InvalidProfile);
    }
    Ok(())
}

fn quoted_value_start(after_key: &str) -> Option<usize> {
    let colon = after_key.find(':')?;
    let after_colon = &after_key[colon + 1..];
    let quote = after_colon.find('"')?;
    Some(colon + 1 + quote + 1)
}

fn contains_forbidden_placeholder(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("...")
        || lower.contains("placeholder")
        || lower.contains("dummy")
        || lower.contains("fictitious")
}

struct Sha1 {
    state: [u32; 5],
    length_bytes: u64,
    buffer: [u8; 64],
    buffer_len: usize,
}

impl Sha1 {
    fn new() -> Self {
        Self {
            state: [
                0x6745_2301,
                0xefcd_ab89,
                0x98ba_dcfe,
                0x1032_5476,
                0xc3d2_e1f0,
            ],
            length_bytes: 0,
            buffer: [0; 64],
            buffer_len: 0,
        }
    }

    fn update(&mut self, mut bytes: &[u8]) {
        self.length_bytes += bytes.len() as u64;
        if self.buffer_len > 0 {
            let take = core::cmp::min(64 - self.buffer_len, bytes.len());
            self.buffer[self.buffer_len..self.buffer_len + take].copy_from_slice(&bytes[..take]);
            self.buffer_len += take;
            bytes = &bytes[take..];
            if self.buffer_len == 64 {
                let block = self.buffer;
                self.process_block(&block);
                self.buffer_len = 0;
            }
        }
        while bytes.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&bytes[..64]);
            self.process_block(&block);
            bytes = &bytes[64..];
        }
        if !bytes.is_empty() {
            self.buffer[..bytes.len()].copy_from_slice(bytes);
            self.buffer_len = bytes.len();
        }
    }

    fn finalize(mut self) -> [u8; SHA1_DIGEST_BYTES] {
        let bit_len = self.length_bytes * 8;
        let mut block = [0u8; 64];
        block[..self.buffer_len].copy_from_slice(&self.buffer[..self.buffer_len]);
        block[self.buffer_len] = 0x80;
        if self.buffer_len >= 56 {
            self.process_block(&block);
            block = [0; 64];
        }
        block[56..64].copy_from_slice(&bit_len.to_be_bytes());
        self.process_block(&block);

        let mut out = [0u8; SHA1_DIGEST_BYTES];
        for (idx, word) in self.state.iter().enumerate() {
            out[idx * 4..idx * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    fn process_block(&mut self, block: &[u8; 64]) {
        let mut words = [0u32; 80];
        for (idx, chunk) in block.chunks_exact(4).enumerate() {
            words[idx] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        for idx in 16..80 {
            words[idx] = (words[idx - 3] ^ words[idx - 8] ^ words[idx - 14] ^ words[idx - 16])
                .rotate_left(1);
        }

        let [mut a, mut b, mut c, mut d, mut e] = self.state;
        for (idx, word) in words.iter().enumerate() {
            let (f, k) = match idx {
                0..=19 => ((b & c) | ((!b) & d), 0x5a82_7999),
                20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
                _ => (b ^ c ^ d, 0xca62_c1d6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{load_profile_set, BuildMode, ConfigLoadPolicy, SignatureStatus};

    const PROFILE: &[u8] = br#"{"profile_class":"CERTIFICATION","profile_source":{"owner":"scheme_or_acquirer","document":"signed_certification_profile_bundle","version":"2","verification":"external_signature_required"},"scheme_profiles":[{"scheme_name":"Visa","rid":"A000000003","kernel_type":"c8_contactless","taa_fallback_when_offline_unable_online":"AAC","taa_no_match_default_when_online_capable":"ARQC","taa_no_match_default_when_offline_only":"AAC","aids":[{"aid":"A0000000031010","priority":1,"partial_selection":true,"interfaces":["contact","contactless"],"tac_online":"0000000000","tac_denial":"0000000000","tac_default":"0000000000","iac_online":"0000000000","iac_denial":"0000000000","iac_default":"0000000000","floor_limit":0,"cvm_limit_contact":0,"random_selection_percent":0,"contactless_transaction_limit":5000,"contactless_cvm_limit":3000,"cdcvm_supported":true,"cda_supported":true}],"capks":[{"key_index":1,"modulus_hex":"D2E5F5B3A1C8D4E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B9C0","exponent_hex":"010001","expiry":"2030-12-31","checksum_hex":"E7BE39F210609E8609E23255BC1B54E81C7EC5D5","source":{"owner":"scheme_or_acquirer","document":"signed_certification_capk_bundle","version":"2","verification":"external_signature_required"}}]}]}"#;

    #[test]
    fn selects_strongest_allowed_oda_method_without_fallback_after_cda_failure() {
        assert_eq!(
            select_oda_method(selection_input_from_aip([0xc0, 0x80], true, true)),
            OdaSelection::Perform(OdaMethod::Cda)
        );

        let selection = select_oda_method(OdaSelectionInput {
            aip_sda_supported: true,
            aip_dda_supported: true,
            aip_cda_supported: true,
            profile_sda_allowed: true,
            profile_dda_allowed: true,
            profile_cda_allowed: true,
            terminal_supports_dynamic_authentication: true,
            oda_required: true,
        });
        assert_eq!(selection, OdaSelection::Perform(OdaMethod::Cda));

        let (tvr, tsi) = apply_oda_outcome(
            Tvr::cleared(),
            Tsi::cleared(),
            OdaOutcome::Failed {
                method: OdaMethod::Cda,
                failure: OdaFailure::CdaSignature,
            },
        );
        assert!(tvr.is_set(Tvr::B1_CDA_FAILED));
        assert!(!tvr.is_set(Tvr::B1_DDA_FAILED));
        assert!(tsi.is_set(Tsi::OFFLINE_DATA_AUTHENTICATION_PERFORMED));
    }

    #[test]
    fn marks_oda_not_performed_when_required_but_unavailable() {
        let selection = select_oda_method(OdaSelectionInput {
            aip_sda_supported: false,
            aip_dda_supported: false,
            aip_cda_supported: false,
            profile_sda_allowed: true,
            profile_dda_allowed: true,
            profile_cda_allowed: true,
            terminal_supports_dynamic_authentication: true,
            oda_required: true,
        });
        assert_eq!(selection, OdaSelection::NotPerformedRequired);
        let (tvr, _) = apply_oda_outcome(Tvr::cleared(), Tsi::cleared(), OdaOutcome::NotPerformed);
        assert!(tvr.is_set(Tvr::B1_OFFLINE_DATA_AUTH_NOT_PERFORMED));
    }

    #[test]
    fn certificate_recovery_failures_set_missing_icc_data_and_method_bits() {
        let (tvr, tsi) = apply_oda_outcome(
            Tvr::cleared(),
            Tsi::cleared(),
            OdaOutcome::Failed {
                method: OdaMethod::Sda,
                failure: OdaFailure::IssuerCertificateRecovery,
            },
        );
        assert!(tvr.is_set(Tvr::B1_ICC_DATA_MISSING));
        assert!(tvr.is_set(Tvr::B1_SDA_FAILED));
        assert!(tsi.is_set(Tsi::OFFLINE_DATA_AUTHENTICATION_PERFORMED));

        let (tvr, _) = apply_oda_outcome(
            Tvr::cleared(),
            Tsi::cleared(),
            OdaOutcome::Failed {
                method: OdaMethod::Dda,
                failure: OdaFailure::IccCertificateRecovery,
            },
        );
        assert!(tvr.is_set(Tvr::B1_ICC_DATA_MISSING));
        assert!(tvr.is_set(Tvr::B1_DDA_FAILED));

        let (tvr, _) = apply_oda_outcome(
            Tvr::cleared(),
            Tsi::cleared(),
            OdaOutcome::Failed {
                method: OdaMethod::Cda,
                failure: OdaFailure::CdaSignature,
            },
        );
        assert!(!tvr.is_set(Tvr::B1_ICC_DATA_MISSING));
        assert!(tvr.is_set(Tvr::B1_CDA_FAILED));
    }

    #[test]
    fn capk_lookup_requires_verified_integrity_and_unexpired_key() {
        let policy = ConfigLoadPolicy {
            mode: BuildMode::Certification,
            signature_status: SignatureStatus::Verified,
            installed_version: 1,
            candidate_version: 2,
            evaluation_date: EmvDate {
                year: 26,
                month: 5,
                day: 21,
            },
        };
        let mut profiles = load_profile_set(PROFILE, &policy).unwrap();
        let rid = [0xa0, 0x00, 0x00, 0x00, 0x03];

        assert_eq!(
            select_capk(
                &profiles,
                &rid,
                1,
                policy.evaluation_date,
                CapkIntegrity::Unverified
            )
            .unwrap_err(),
            KernelError::InvalidProfile
        );
        assert_eq!(
            select_capk(
                &profiles,
                &rid,
                2,
                policy.evaluation_date,
                CapkIntegrity::Verified
            )
            .unwrap_err(),
            KernelError::MissingMandatoryTag
        );
        let capk = select_capk(
            &profiles,
            &rid,
            1,
            policy.evaluation_date,
            CapkIntegrity::Verified,
        )
        .unwrap();
        assert_eq!(capk.key_index, 1);

        profiles.schemes[0].capks[0].checksum[0] ^= 0xff;
        assert_eq!(
            select_capk(
                &profiles,
                &rid,
                1,
                policy.evaluation_date,
                CapkIntegrity::Verified,
            )
            .unwrap_err(),
            KernelError::MissingMandatoryTag
        );
    }

    #[test]
    fn sha1_matches_standard_vectors() {
        let mut sha1 = Sha1::new();
        sha1.update(b"");
        assert_eq!(
            sha1.finalize(),
            decode_hex("DA39A3EE5E6B4B0D3255BFEF95601890AFD80709")
                .unwrap()
                .as_slice()
        );

        let mut sha1 = Sha1::new();
        sha1.update(b"abc");
        assert_eq!(
            sha1.finalize(),
            decode_hex("A9993E364706816ABA3E25717850C26C9CD0D89D")
                .unwrap()
                .as_slice()
        );
    }

    #[test]
    fn parses_internal_authenticate_response_signed_dynamic_data() {
        let response = parse_internal_authenticate_response(&[
            0x77, 0x12, 0x9f, 0x4b, 0x08, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0x9f,
            0x4c, 0x04, 0x01, 0x02, 0x03, 0x04,
        ])
        .unwrap();
        assert_eq!(
            response.signed_dynamic_application_data,
            vec![0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8]
        );
        assert_eq!(response.icc_dynamic_number, Some(vec![1, 2, 3, 4]));

        assert_eq!(
            parse_internal_authenticate_response(&[0x77, 0x03, 0x9f, 0x4c, 0x00]).unwrap_err(),
            KernelError::MissingMandatoryTag
        );
        assert_eq!(
            parse_internal_authenticate_response(&[0x9f, 0x4b, 0x02, 0xaa, 0xbb]).unwrap_err(),
            KernelError::InvalidProfile
        );
    }

    #[test]
    fn validates_complete_vector_syntax_and_rejects_placeholders() {
        let complete = br#"{"test_vectors":[{"id":"SDA","capk":{"rid":"A000000003","key_index":1,"modulus_hex":"D2E5F5B3A1C8D4E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0","exponent_hex":"010001","checksum_hex":"A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8"},"issuer_certificate_hex":"6F2A9F103A1B2C3D4E5F60718293A4B5C6D7E8F9A0","static_signature_hex":"ABCD1234567890ABCD","expected_tvr":"0000000000","expected_oda_result":"PASS"}]}"#;
        validate_oda_vector_annex(complete, true).unwrap();

        let placeholder = br#"{"test_vectors":[{"issuer_certificate_hex":"...","expected_tvr":"0000000000","expected_oda_result":"PASS"}]}"#;
        assert_eq!(
            validate_oda_vector_annex(placeholder, true).unwrap_err(),
            KernelError::InvalidProfile
        );
    }
}
