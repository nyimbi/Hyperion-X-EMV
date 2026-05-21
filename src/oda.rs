use crate::config::{decode_hex, Capk, ProfileSet};
use crate::error::{KernelError, KernelResult};
use crate::restrictions::EmvDate;
use crate::state::{Tsi, Tvr};

pub const MIN_ODA_CERTIFICATE_BYTES: usize = 16;
pub const MIN_ODA_SIGNATURE_BYTES: usize = 8;

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
    profiles
        .schemes
        .iter()
        .find(|scheme| &scheme.rid == rid)
        .and_then(|scheme| {
            scheme
                .capks
                .iter()
                .find(|capk| capk.key_index == key_index && capk.expiry >= evaluation_date)
        })
        .ok_or(KernelError::MissingMandatoryTag)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{load_profile_set, BuildMode, ConfigLoadPolicy, SignatureStatus};

    const PROFILE: &[u8] = br#"{"profile_class":"CERTIFICATION","profile_source":{"owner":"scheme_or_acquirer","document":"signed_certification_profile_bundle","version":"2","verification":"external_signature_required"},"scheme_profiles":[{"scheme_name":"Visa","rid":"A000000003","kernel_type":"c8_contactless","taa_fallback_when_offline_unable_online":"AAC","taa_no_match_default_when_online_capable":"ARQC","taa_no_match_default_when_offline_only":"AAC","aids":[{"aid":"A0000000031010","priority":1,"partial_selection":true,"interfaces":["contact","contactless"],"tac_online":"0000000000","tac_denial":"0000000000","tac_default":"0000000000","iac_online":"0000000000","iac_denial":"0000000000","iac_default":"0000000000","floor_limit":0,"cvm_limit_contact":0,"random_selection_percent":0,"contactless_transaction_limit":5000,"contactless_cvm_limit":3000,"cdcvm_supported":true,"cda_supported":true}],"capks":[{"key_index":1,"modulus_hex":"D2E5F5B3A1C8D4E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B9C0","exponent_hex":"010001","expiry":"2030-12-31","checksum_hex":"A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8"}]}]}"#;

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
        let profiles = load_profile_set(PROFILE, &policy).unwrap();
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
