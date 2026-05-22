use crate::config::{decode_hex, Capk, ProfileSet};
use crate::dol::DataStore;
use crate::error::{KernelError, KernelResult};
use crate::restrictions::EmvDate;
use crate::sha1::{Sha1, SHA1_DIGEST_BYTES};
use crate::state::{Tsi, Tvr};
use crate::tlv;
use core::fmt;

pub const MIN_ODA_CERTIFICATE_BYTES: usize = 16;
pub const MIN_ODA_SIGNATURE_BYTES: usize = 8;
pub const MAX_ODA_REMAINDER_BYTES: usize = 248;
pub const MAX_ODA_RSA_MODULUS_BYTES: usize = 256;
pub const MAX_ODA_AUTHENTICATION_DATA_BYTES: usize = 65_535;
const EMV_SHA1_HASH_ALGORITHM_INDICATOR: u8 = 0x01;
const EMV_RSA_PUBLIC_KEY_ALGORITHM_INDICATOR: u8 = 0x01;
const RECOVERED_CERTIFICATE_HEADER: u8 = 0x6a;
const RECOVERED_CERTIFICATE_TRAILER: u8 = 0xbc;
const MIN_RECOVERED_CERTIFICATE_BYTES: usize = 35;
const RECOVERED_SIGNED_DATA_HEADER: u8 = 0x6a;
const RECOVERED_SIGNED_DATA_TRAILER: u8 = 0xbc;
const RECOVERED_SIGNED_STATIC_DATA_FORMAT: u8 = 0x03;
const RECOVERED_SIGNED_DYNAMIC_DATA_FORMAT: u8 = 0x05;
const RECOVERED_PADDING_BYTE: u8 = 0xbb;
const MAX_STATIC_AUTH_TAG_LIST_TAGS: usize = 16;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveredCertificateKind {
    Issuer,
    Icc,
}

impl RecoveredCertificateKind {
    fn certificate_format(self) -> u8 {
        match self {
            Self::Issuer => 0x02,
            Self::Icc => 0x04,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveredSignedDataKind {
    StaticApplicationData,
    DynamicApplicationData,
}

impl RecoveredSignedDataKind {
    fn signed_data_format(self) -> u8 {
        match self {
            Self::StaticApplicationData => RECOVERED_SIGNED_STATIC_DATA_FORMAT,
            Self::DynamicApplicationData => RECOVERED_SIGNED_DYNAMIC_DATA_FORMAT,
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct InternalAuthenticateResponse {
    pub signed_dynamic_application_data: Vec<u8>,
    pub icc_dynamic_number: Option<Vec<u8>>,
}

impl fmt::Debug for InternalAuthenticateResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InternalAuthenticateResponse")
            .field(
                "signed_dynamic_application_data_len",
                &self.signed_dynamic_application_data.len(),
            )
            .field(
                "icc_dynamic_number_len",
                &self.icc_dynamic_number.as_ref().map(Vec::len),
            )
            .field(
                "data_policy",
                &"ODA authentication data redacted for crash safety",
            )
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct PublicKeyInput {
    pub certificate: Vec<u8>,
    pub remainder: Vec<u8>,
    pub exponent: Vec<u8>,
}

impl fmt::Debug for PublicKeyInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicKeyInput")
            .field("certificate_len", &self.certificate.len())
            .field("remainder_len", &self.remainder.len())
            .field("exponent_len", &self.exponent.len())
            .field(
                "data_policy",
                &"ODA public-key input bytes redacted for crash safety",
            )
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct StaticAuthenticationRecord {
    pub sfi: u8,
    pub record: u8,
    pub body: Vec<u8>,
}

impl fmt::Debug for StaticAuthenticationRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StaticAuthenticationRecord")
            .field("sfi", &self.sfi)
            .field("record", &self.record)
            .field("body_len", &self.body.len())
            .field(
                "data_policy",
                &"static authentication record body redacted for crash safety",
            )
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct RecoveredPublicKeyCertificate {
    pub kind: RecoveredCertificateKind,
    pub identifier: [u8; 10],
    pub expiration_date: [u8; 2],
    pub serial_number: [u8; 3],
    pub hash_algorithm_indicator: u8,
    pub public_key_algorithm_indicator: u8,
    pub public_key: Vec<u8>,
    pub exponent: Vec<u8>,
    pub hash_result: [u8; SHA1_DIGEST_BYTES],
}

impl fmt::Debug for RecoveredPublicKeyCertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveredPublicKeyCertificate")
            .field("kind", &self.kind)
            .field("expiration_date", &self.expiration_date)
            .field("hash_algorithm_indicator", &self.hash_algorithm_indicator)
            .field(
                "public_key_algorithm_indicator",
                &self.public_key_algorithm_indicator,
            )
            .field("public_key_len", &self.public_key.len())
            .field("exponent_len", &self.exponent.len())
            .field(
                "data_policy",
                &"certificate identifiers, serials, public-key bytes, and hash bytes redacted for crash safety",
            )
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct RecoveredSignedApplicationData {
    pub kind: RecoveredSignedDataKind,
    pub hash_algorithm_indicator: u8,
    pub data_authentication_code: Option<[u8; 2]>,
    pub icc_dynamic_data: Option<Vec<u8>>,
    pub padding: Vec<u8>,
    pub hash_result: [u8; SHA1_DIGEST_BYTES],
}

impl fmt::Debug for RecoveredSignedApplicationData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveredSignedApplicationData")
            .field("kind", &self.kind)
            .field("hash_algorithm_indicator", &self.hash_algorithm_indicator)
            .field(
                "data_authentication_code_present",
                &self.data_authentication_code.is_some(),
            )
            .field(
                "icc_dynamic_data_len",
                &self.icc_dynamic_data.as_ref().map(Vec::len),
            )
            .field("padding_len", &self.padding.len())
            .field(
                "data_policy",
                &"signed application data and hash bytes redacted for crash safety",
            )
            .finish()
    }
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
    crate::config::capk_checksum_components(
        &capk.rid,
        capk.key_index,
        &capk.modulus,
        &capk.exponent,
    )
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
    if tlvs.len() != 1 || tlvs[0].tag != [0x77] || !tlvs[0].constructed {
        return Err(KernelError::MissingMandatoryTag);
    }
    reject_constructed_internal_authenticate_children(&tlvs[0].children)?;

    let signed_dynamic_application_data =
        tlv::find_unique_direct(&tlvs[0].children, &[0x9f, 0x4b])?
            .ok_or(KernelError::MissingMandatoryTag)?;
    if signed_dynamic_application_data.len() < MIN_ODA_SIGNATURE_BYTES {
        return Err(KernelError::InvalidProfile);
    }
    let icc_dynamic_number = match tlv::find_unique_direct(&tlvs[0].children, &[0x9f, 0x4c])? {
        Some([]) => return Err(KernelError::ParseError),
        Some(value) => Some(value.to_vec()),
        None => None,
    };

    Ok(InternalAuthenticateResponse {
        signed_dynamic_application_data: signed_dynamic_application_data.to_vec(),
        icc_dynamic_number,
    })
}

fn reject_constructed_internal_authenticate_children(
    children: &[tlv::Tlv<'_>],
) -> KernelResult<()> {
    if children.iter().any(|child| child.constructed) {
        return Err(KernelError::ParseError);
    }
    Ok(())
}

pub fn validate_issuer_public_key_inputs(data: &DataStore) -> KernelResult<PublicKeyInput> {
    validate_public_key_inputs(
        data.get(&[0x90]),
        data.get(&[0x92]),
        data.get(&[0x9f, 0x32]),
    )
}

pub fn validate_icc_public_key_inputs(data: &DataStore) -> KernelResult<PublicKeyInput> {
    validate_public_key_inputs(
        data.get(&[0x9f, 0x46]),
        data.get(&[0x9f, 0x48]),
        data.get(&[0x9f, 0x47]),
    )
}

pub fn build_static_authentication_data(
    records: &[StaticAuthenticationRecord],
    data: &DataStore,
) -> KernelResult<Vec<u8>> {
    if records.is_empty() {
        return Err(KernelError::MissingMandatoryTag);
    }

    let mut out = Vec::new();
    for record in records {
        if record.sfi == 0 || record.sfi > 30 || record.record == 0 || record.body.is_empty() {
            return Err(KernelError::InvalidArgument);
        }
        let contribution = static_authentication_record_bytes(record)?;
        append_authentication_data(&mut out, contribution)?;
    }

    if let Some(tag_list) = data.get(&[0x9f, 0x4a]) {
        let tags = parse_static_authentication_tag_list(tag_list)?;
        for tag in tags {
            let value = data.get(&tag).ok_or(KernelError::MissingMandatoryTag)?;
            append_authentication_data(&mut out, value)?;
        }
    }

    Ok(out)
}

pub fn parse_recovered_public_key_certificate(
    kind: RecoveredCertificateKind,
    recovered: &[u8],
    remainder: &[u8],
    exponent: &[u8],
) -> KernelResult<RecoveredPublicKeyCertificate> {
    if recovered.len() < MIN_RECOVERED_CERTIFICATE_BYTES {
        return Err(KernelError::ParseError);
    }
    if recovered[0] != RECOVERED_CERTIFICATE_HEADER
        || recovered[1] != kind.certificate_format()
        || *recovered.last().ok_or(KernelError::ParseError)? != RECOVERED_CERTIFICATE_TRAILER
    {
        return Err(KernelError::InvalidProfile);
    }

    let mut cursor = 2usize;
    let identifier = fixed_from_slice::<10>(recovered, &mut cursor)?;
    let expiration_date = fixed_from_slice::<2>(recovered, &mut cursor)?;
    let serial_number = fixed_from_slice::<3>(recovered, &mut cursor)?;
    let hash_algorithm_indicator = next_recovered_byte(recovered, &mut cursor)?;
    let public_key_algorithm_indicator = next_recovered_byte(recovered, &mut cursor)?;
    let public_key_length = next_recovered_byte(recovered, &mut cursor)? as usize;
    let exponent_length = next_recovered_byte(recovered, &mut cursor)? as usize;
    if public_key_length == 0 || exponent_length == 0 || exponent.len() != exponent_length {
        return Err(KernelError::InvalidProfile);
    }

    let fragment_end = recovered
        .len()
        .checked_sub(SHA1_DIGEST_BYTES + 1)
        .ok_or(KernelError::ParseError)?;
    if cursor >= fragment_end {
        return Err(KernelError::ParseError);
    }
    let fragment = &recovered[cursor..fragment_end];
    if fragment.is_empty() || all_zero_or_ff(fragment) {
        return Err(KernelError::InvalidProfile);
    }
    let mut public_key = Vec::with_capacity(fragment.len() + remainder.len());
    public_key.extend_from_slice(fragment);
    public_key.extend_from_slice(remainder);
    if public_key.len() != public_key_length {
        return Err(KernelError::InvalidProfile);
    }

    let hash_result = fixed_from_range::<SHA1_DIGEST_BYTES>(recovered, fragment_end)?;
    if all_zero_or_ff(&hash_result) {
        return Err(KernelError::InvalidProfile);
    }

    Ok(RecoveredPublicKeyCertificate {
        kind,
        identifier,
        expiration_date,
        serial_number,
        hash_algorithm_indicator,
        public_key_algorithm_indicator,
        public_key,
        exponent: exponent.to_vec(),
        hash_result,
    })
}

pub fn recovered_public_key_certificate_hash_input(
    certificate: &RecoveredPublicKeyCertificate,
    authentication_data: &[u8],
) -> KernelResult<Vec<u8>> {
    let public_key_len =
        u8::try_from(certificate.public_key.len()).map_err(|_| KernelError::LengthOverflow)?;
    let exponent_len =
        u8::try_from(certificate.exponent.len()).map_err(|_| KernelError::LengthOverflow)?;
    let mut input = Vec::with_capacity(
        1 + certificate.identifier.len()
            + certificate.expiration_date.len()
            + certificate.serial_number.len()
            + 4
            + certificate.public_key.len()
            + certificate.exponent.len()
            + authentication_data.len(),
    );
    input.push(certificate.kind.certificate_format());
    input.extend_from_slice(&certificate.identifier);
    input.extend_from_slice(&certificate.expiration_date);
    input.extend_from_slice(&certificate.serial_number);
    input.push(certificate.hash_algorithm_indicator);
    input.push(certificate.public_key_algorithm_indicator);
    input.push(public_key_len);
    input.push(exponent_len);
    input.extend_from_slice(&certificate.public_key);
    input.extend_from_slice(&certificate.exponent);
    input.extend_from_slice(authentication_data);
    Ok(input)
}

pub fn recovered_public_key_certificate_hash(
    certificate: &RecoveredPublicKeyCertificate,
    authentication_data: &[u8],
) -> KernelResult<[u8; SHA1_DIGEST_BYTES]> {
    if certificate.hash_algorithm_indicator != EMV_SHA1_HASH_ALGORITHM_INDICATOR
        || certificate.public_key_algorithm_indicator != EMV_RSA_PUBLIC_KEY_ALGORITHM_INDICATOR
    {
        return Err(KernelError::InvalidProfile);
    }
    let mut sha1 = Sha1::new();
    let hash_input = recovered_public_key_certificate_hash_input(certificate, authentication_data)?;
    sha1.update(&hash_input);
    Ok(sha1.finalize())
}

pub fn recovered_public_key_certificate_hash_is_valid(
    certificate: &RecoveredPublicKeyCertificate,
    authentication_data: &[u8],
) -> KernelResult<bool> {
    Ok(
        recovered_public_key_certificate_hash(certificate, authentication_data)?
            == certificate.hash_result,
    )
}

pub fn recover_and_verify_public_key_certificate(
    kind: RecoveredCertificateKind,
    certificate_signature: &[u8],
    signing_modulus: &[u8],
    signing_exponent: &[u8],
    public_key_remainder: &[u8],
    public_key_exponent: &[u8],
    authentication_data: &[u8],
) -> KernelResult<RecoveredPublicKeyCertificate> {
    let recovered =
        recover_rsa_public_block(certificate_signature, signing_modulus, signing_exponent)?;
    let certificate = parse_recovered_public_key_certificate(
        kind,
        &recovered,
        public_key_remainder,
        public_key_exponent,
    )?;
    if !recovered_public_key_certificate_hash_is_valid(&certificate, authentication_data)? {
        return Err(KernelError::InvalidProfile);
    }
    Ok(certificate)
}

pub fn parse_recovered_signed_application_data(
    kind: RecoveredSignedDataKind,
    recovered: &[u8],
) -> KernelResult<RecoveredSignedApplicationData> {
    if recovered.len() < MIN_ODA_SIGNATURE_BYTES + SHA1_DIGEST_BYTES {
        return Err(KernelError::ParseError);
    }
    if recovered[0] != RECOVERED_SIGNED_DATA_HEADER
        || recovered[1] != kind.signed_data_format()
        || *recovered.last().ok_or(KernelError::ParseError)? != RECOVERED_SIGNED_DATA_TRAILER
    {
        return Err(KernelError::InvalidProfile);
    }

    let mut cursor = 2usize;
    let hash_algorithm_indicator = next_recovered_byte(recovered, &mut cursor)?;
    let hash_start = recovered
        .len()
        .checked_sub(SHA1_DIGEST_BYTES + 1)
        .ok_or(KernelError::ParseError)?;
    if cursor >= hash_start {
        return Err(KernelError::ParseError);
    }

    let (data_authentication_code, icc_dynamic_data, padding) = match kind {
        RecoveredSignedDataKind::StaticApplicationData => {
            let data_authentication_code = fixed_from_slice::<2>(recovered, &mut cursor)?;
            let padding = recovered
                .get(cursor..hash_start)
                .ok_or(KernelError::ParseError)?
                .to_vec();
            (Some(data_authentication_code), None, padding)
        }
        RecoveredSignedDataKind::DynamicApplicationData => {
            let dynamic_data_length = next_recovered_byte(recovered, &mut cursor)? as usize;
            if dynamic_data_length == 0 {
                return Err(KernelError::InvalidProfile);
            }
            let dynamic_data_end = cursor
                .checked_add(dynamic_data_length)
                .ok_or(KernelError::LengthOverflow)?;
            if dynamic_data_end > hash_start {
                return Err(KernelError::ParseError);
            }
            let icc_dynamic_data = recovered[cursor..dynamic_data_end].to_vec();
            cursor = dynamic_data_end;
            let padding = recovered
                .get(cursor..hash_start)
                .ok_or(KernelError::ParseError)?
                .to_vec();
            (None, Some(icc_dynamic_data), padding)
        }
    };

    if padding.iter().any(|byte| *byte != RECOVERED_PADDING_BYTE) {
        return Err(KernelError::InvalidProfile);
    }
    let hash_result = fixed_from_range::<SHA1_DIGEST_BYTES>(recovered, hash_start)?;
    if all_zero_or_ff(&hash_result) {
        return Err(KernelError::InvalidProfile);
    }

    Ok(RecoveredSignedApplicationData {
        kind,
        hash_algorithm_indicator,
        data_authentication_code,
        icc_dynamic_data,
        padding,
        hash_result,
    })
}

pub fn recovered_signed_application_data_hash_input(
    signed_data: &RecoveredSignedApplicationData,
    authentication_data: &[u8],
) -> KernelResult<Vec<u8>> {
    let mut input = Vec::with_capacity(
        2 + signed_data
            .data_authentication_code
            .map(|value| value.len())
            .unwrap_or(0)
            + signed_data
                .icc_dynamic_data
                .as_ref()
                .map(|value| 1 + value.len())
                .unwrap_or(0)
            + signed_data.padding.len()
            + authentication_data.len(),
    );
    input.push(signed_data.kind.signed_data_format());
    input.push(signed_data.hash_algorithm_indicator);
    match signed_data.kind {
        RecoveredSignedDataKind::StaticApplicationData => {
            input.extend_from_slice(
                &signed_data
                    .data_authentication_code
                    .ok_or(KernelError::InvalidProfile)?,
            );
            if signed_data.icc_dynamic_data.is_some() {
                return Err(KernelError::InvalidProfile);
            }
        }
        RecoveredSignedDataKind::DynamicApplicationData => {
            let dynamic_data = signed_data
                .icc_dynamic_data
                .as_ref()
                .ok_or(KernelError::InvalidProfile)?;
            let dynamic_data_len =
                u8::try_from(dynamic_data.len()).map_err(|_| KernelError::LengthOverflow)?;
            input.push(dynamic_data_len);
            input.extend_from_slice(dynamic_data);
            if signed_data.data_authentication_code.is_some() {
                return Err(KernelError::InvalidProfile);
            }
        }
    }
    input.extend_from_slice(&signed_data.padding);
    input.extend_from_slice(authentication_data);
    Ok(input)
}

pub fn recovered_signed_application_data_hash(
    signed_data: &RecoveredSignedApplicationData,
    authentication_data: &[u8],
) -> KernelResult<[u8; SHA1_DIGEST_BYTES]> {
    if signed_data.hash_algorithm_indicator != EMV_SHA1_HASH_ALGORITHM_INDICATOR {
        return Err(KernelError::InvalidProfile);
    }
    if signed_data
        .padding
        .iter()
        .any(|byte| *byte != RECOVERED_PADDING_BYTE)
    {
        return Err(KernelError::InvalidProfile);
    }
    let mut sha1 = Sha1::new();
    let hash_input =
        recovered_signed_application_data_hash_input(signed_data, authentication_data)?;
    sha1.update(&hash_input);
    Ok(sha1.finalize())
}

pub fn recovered_signed_application_data_hash_is_valid(
    signed_data: &RecoveredSignedApplicationData,
    authentication_data: &[u8],
) -> KernelResult<bool> {
    Ok(
        recovered_signed_application_data_hash(signed_data, authentication_data)?
            == signed_data.hash_result,
    )
}

pub fn recover_and_verify_signed_application_data(
    kind: RecoveredSignedDataKind,
    signed_data_signature: &[u8],
    signing_modulus: &[u8],
    signing_exponent: &[u8],
    authentication_data: &[u8],
) -> KernelResult<RecoveredSignedApplicationData> {
    let recovered =
        recover_rsa_public_block(signed_data_signature, signing_modulus, signing_exponent)?;
    let signed_data = parse_recovered_signed_application_data(kind, &recovered)?;
    if !recovered_signed_application_data_hash_is_valid(&signed_data, authentication_data)? {
        return Err(KernelError::InvalidProfile);
    }
    Ok(signed_data)
}

pub fn verify_static_data_authentication(
    issuer_public_key: &RecoveredPublicKeyCertificate,
    signed_static_application_data: &[u8],
    records: &[StaticAuthenticationRecord],
    data: &DataStore,
) -> KernelResult<RecoveredSignedApplicationData> {
    if issuer_public_key.kind != RecoveredCertificateKind::Issuer {
        return Err(KernelError::InvalidProfile);
    }
    let authentication_data = build_static_authentication_data(records, data)?;
    recover_and_verify_signed_application_data(
        RecoveredSignedDataKind::StaticApplicationData,
        signed_static_application_data,
        &issuer_public_key.public_key,
        &issuer_public_key.exponent,
        &authentication_data,
    )
}

pub fn recover_rsa_public_block(
    signature: &[u8],
    modulus: &[u8],
    exponent: &[u8],
) -> KernelResult<Vec<u8>> {
    let exponent = parse_rsa_public_exponent(exponent)?;
    validate_rsa_public_components(signature, modulus)?;

    let mut result = vec![0u8; modulus.len()];
    *result.last_mut().ok_or(KernelError::InvalidProfile)? = 1;
    let mut base = signature.to_vec();
    let mut remaining_exponent = exponent;

    while remaining_exponent > 0 {
        if remaining_exponent & 1 == 1 {
            result = mod_mul_be(&result, &base, modulus)?;
        }
        remaining_exponent >>= 1;
        if remaining_exponent > 0 {
            base = mod_mul_be(&base, &base, modulus)?;
        }
    }

    Ok(result)
}

fn validate_public_key_inputs(
    certificate: Option<&[u8]>,
    remainder: Option<&[u8]>,
    exponent: Option<&[u8]>,
) -> KernelResult<PublicKeyInput> {
    let certificate = certificate.ok_or(KernelError::MissingMandatoryTag)?;
    if certificate.len() < MIN_ODA_CERTIFICATE_BYTES || all_zero_or_ff(certificate) {
        return Err(KernelError::InvalidProfile);
    }

    let remainder = remainder.unwrap_or(&[]);
    if remainder.len() > MAX_ODA_REMAINDER_BYTES
        || (!remainder.is_empty() && all_zero_or_ff(remainder))
    {
        return Err(KernelError::InvalidProfile);
    }

    let exponent = exponent.ok_or(KernelError::MissingMandatoryTag)?;
    if exponent.is_empty() || exponent.len() > 3 || all_zero_or_ff(exponent) {
        return Err(KernelError::InvalidProfile);
    }

    Ok(PublicKeyInput {
        certificate: certificate.to_vec(),
        remainder: remainder.to_vec(),
        exponent: exponent.to_vec(),
    })
}

fn static_authentication_record_bytes(record: &StaticAuthenticationRecord) -> KernelResult<&[u8]> {
    if record.sfi <= 10 {
        let tlvs = tlv::parse_many(&record.body)?;
        if tlvs.len() != 1 || tlvs[0].tag != [0x70] || !tlvs[0].constructed {
            return Err(KernelError::InvalidProfile);
        }
        Ok(tlvs[0].value)
    } else {
        Ok(&record.body)
    }
}

fn append_authentication_data(out: &mut Vec<u8>, value: &[u8]) -> KernelResult<()> {
    let next_len = out
        .len()
        .checked_add(value.len())
        .ok_or(KernelError::LengthOverflow)?;
    if next_len > MAX_ODA_AUTHENTICATION_DATA_BYTES {
        return Err(KernelError::LengthOverflow);
    }
    out.extend_from_slice(value);
    Ok(())
}

fn parse_static_authentication_tag_list(input: &[u8]) -> KernelResult<Vec<Vec<u8>>> {
    tlv::parse_unique_primitive_tag_list(input, MAX_STATIC_AUTH_TAG_LIST_TAGS)
}

fn parse_rsa_public_exponent(exponent: &[u8]) -> KernelResult<u32> {
    if exponent.is_empty() || exponent.len() > 3 || all_zero_or_ff(exponent) {
        return Err(KernelError::InvalidProfile);
    }
    let mut value = 0u32;
    for byte in exponent {
        value = (value << 8) | u32::from(*byte);
    }
    if value < 3 || value % 2 == 0 {
        return Err(KernelError::InvalidProfile);
    }
    Ok(value)
}

fn validate_rsa_public_components(signature: &[u8], modulus: &[u8]) -> KernelResult<()> {
    if modulus.len() < 2
        || modulus.len() > MAX_ODA_RSA_MODULUS_BYTES
        || modulus[0] == 0
        || modulus[modulus.len() - 1] % 2 == 0
        || all_zero_or_ff(modulus)
    {
        return Err(KernelError::InvalidProfile);
    }
    if signature.len() != modulus.len()
        || all_zero_or_ff(signature)
        || compare_be(signature, modulus) != core::cmp::Ordering::Less
    {
        return Err(KernelError::InvalidProfile);
    }
    Ok(())
}

fn mod_mul_be(a: &[u8], b: &[u8], modulus: &[u8]) -> KernelResult<Vec<u8>> {
    if a.len() != modulus.len() || b.len() != modulus.len() {
        return Err(KernelError::InvalidArgument);
    }
    let mut result = vec![0u8; modulus.len()];
    let mut addend = a.to_vec();

    for byte in b.iter().rev() {
        for bit in 0..8 {
            if byte & (1u8 << bit) != 0 {
                result = mod_add_be(&result, &addend, modulus)?;
            }
            addend = mod_add_be(&addend, &addend, modulus)?;
        }
    }

    Ok(result)
}

fn mod_add_be(a: &[u8], b: &[u8], modulus: &[u8]) -> KernelResult<Vec<u8>> {
    if a.len() != modulus.len() || b.len() != modulus.len() {
        return Err(KernelError::InvalidArgument);
    }
    let mut sum = vec![0u8; modulus.len() + 1];
    let mut carry = 0u16;
    for idx in (0..modulus.len()).rev() {
        let total = u16::from(a[idx]) + u16::from(b[idx]) + carry;
        sum[idx + 1] = total as u8;
        carry = total >> 8;
    }
    sum[0] = carry as u8;

    let mut padded_modulus = Vec::with_capacity(modulus.len() + 1);
    padded_modulus.push(0);
    padded_modulus.extend_from_slice(modulus);
    if compare_be(&sum, &padded_modulus) != core::cmp::Ordering::Less {
        sub_assign_be(&mut sum, &padded_modulus);
    }
    Ok(sum[1..].to_vec())
}

fn compare_be(a: &[u8], b: &[u8]) -> core::cmp::Ordering {
    for (left, right) in a.iter().zip(b.iter()) {
        match left.cmp(right) {
            core::cmp::Ordering::Equal => {}
            ordering => return ordering,
        }
    }
    a.len().cmp(&b.len())
}

fn sub_assign_be(a: &mut [u8], b: &[u8]) {
    let mut borrow = 0i16;
    for idx in (0..a.len()).rev() {
        let value = i16::from(a[idx]) - i16::from(b[idx]) - borrow;
        if value < 0 {
            a[idx] = (value + 256) as u8;
            borrow = 1;
        } else {
            a[idx] = value as u8;
            borrow = 0;
        }
    }
}

fn next_recovered_byte(recovered: &[u8], cursor: &mut usize) -> KernelResult<u8> {
    let value = *recovered.get(*cursor).ok_or(KernelError::ParseError)?;
    *cursor += 1;
    Ok(value)
}

fn fixed_from_slice<const N: usize>(recovered: &[u8], cursor: &mut usize) -> KernelResult<[u8; N]> {
    let end = cursor.checked_add(N).ok_or(KernelError::LengthOverflow)?;
    let value = fixed_from_range::<N>(recovered, *cursor)?;
    *cursor = end;
    Ok(value)
}

fn fixed_from_range<const N: usize>(recovered: &[u8], start: usize) -> KernelResult<[u8; N]> {
    let end = start.checked_add(N).ok_or(KernelError::LengthOverflow)?;
    let bytes = recovered.get(start..end).ok_or(KernelError::ParseError)?;
    let mut out = [0u8; N];
    out.copy_from_slice(bytes);
    Ok(out)
}

pub fn validate_oda_vector_annex(json: &[u8], certification: bool) -> KernelResult<()> {
    let text = core::str::from_utf8(json).map_err(|_| KernelError::ParseError)?;
    match required_json_string_field(text, "vector_class")? {
        "CERTIFICATION" => {}
        "STRUCTURAL_FIXTURE" if !certification => {}
        _ => return Err(KernelError::InvalidProfile),
    }

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
    if certification {
        validate_certification_vector_coverage(text)?;
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

fn validate_certification_vector_coverage(text: &str) -> KernelResult<()> {
    let sda = required_json_object_with_string_field_prefix(text, "id", "SDA")?;
    require_json_fields(
        sda,
        &[
            "\"capk\"",
            "\"issuer_certificate_hex\"",
            "\"static_signature_hex\"",
            "\"expected_tvr\"",
            "\"expected_oda_result\"",
        ],
    )?;

    let dda = required_json_object_with_string_field_prefix(text, "id", "DDA")?;
    require_json_fields(
        dda,
        &[
            "\"capk\"",
            "\"issuer_certificate_hex\"",
            "\"icc_certificate_hex\"",
            "\"ddol_input_hex\"",
            "\"internal_auth_response_hex\"",
            "\"expected_tvr\"",
            "\"expected_oda_result\"",
        ],
    )?;

    let cda = required_json_object_with_string_field_prefix(text, "id", "CDA")?;
    require_json_fields(
        cda,
        &[
            "\"capk\"",
            "\"issuer_certificate_hex\"",
            "\"icc_certificate_hex\"",
            "\"generate_ac_response_hex\"",
            "\"cda_request_bit_used\"",
            "\"expected_tvr\"",
            "\"expected_oda_result\"",
        ],
    )?;

    Ok(())
}

fn require_json_fields(text: &str, fields: &[&str]) -> KernelResult<()> {
    for field in fields {
        if !text.contains(field) {
            return Err(KernelError::InvalidProfile);
        }
    }
    Ok(())
}

fn all_zero_or_ff(value: &[u8]) -> bool {
    value.iter().all(|byte| *byte == 0x00) || value.iter().all(|byte| *byte == 0xff)
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

fn required_json_string_field<'a>(text: &'a str, key: &str) -> KernelResult<&'a str> {
    let pattern = format!("\"{key}\"");
    let key_start = text.find(&pattern).ok_or(KernelError::InvalidProfile)?;
    let value_start = quoted_value_start(&text[key_start + pattern.len()..])
        .map(|offset| key_start + pattern.len() + offset)
        .ok_or(KernelError::ParseError)?;
    let value_end = text[value_start..]
        .find('"')
        .map(|offset| value_start + offset)
        .ok_or(KernelError::ParseError)?;
    Ok(&text[value_start..value_end])
}

fn required_json_object_with_string_field_prefix<'a>(
    text: &'a str,
    key: &str,
    prefix: &str,
) -> KernelResult<&'a str> {
    let pattern = format!("\"{key}\"");
    let mut search_from = 0usize;
    while let Some(relative) = text[search_from..].find(&pattern) {
        let key_start = search_from + relative;
        let value_start = quoted_value_start(&text[key_start + pattern.len()..])
            .map(|offset| key_start + pattern.len() + offset)
            .ok_or(KernelError::ParseError)?;
        let value_end = text[value_start..]
            .find('"')
            .map(|offset| value_start + offset)
            .ok_or(KernelError::ParseError)?;
        if text[value_start..value_end].starts_with(prefix) {
            let object_start = text[..key_start]
                .rfind('{')
                .ok_or(KernelError::ParseError)?;
            let object_end = matching_json_object_end(text, object_start)?;
            return Ok(&text[object_start..=object_end]);
        }
        search_from = value_end + 1;
    }
    Err(KernelError::InvalidProfile)
}

fn matching_json_object_end(text: &str, object_start: usize) -> KernelResult<usize> {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;

    for (relative, ch) in text[object_start..].char_indices() {
        let absolute = object_start + relative;
        if in_string {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }

        match ch {
            '"' => in_string = true,
            '{' => depth = depth.checked_add(1).ok_or(KernelError::LengthOverflow)?,
            '}' => {
                depth = depth.checked_sub(1).ok_or(KernelError::ParseError)?;
                if depth == 0 {
                    return Ok(absolute);
                }
            }
            _ => {}
        }
    }

    Err(KernelError::ParseError)
}

fn contains_forbidden_placeholder(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("...")
        || lower.contains("placeholder")
        || lower.contains("dummy")
        || lower.contains("fictitious")
        || lower.contains("fixture")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{load_profile_set, BuildMode, ConfigLoadPolicy, SignatureStatus};

    const PROFILE: &[u8] = br#"{"profile_class":"CERTIFICATION","profile_source":{"owner":"scheme_or_acquirer","document":"signed_certification_profile_bundle","version":"2","verification":"external_signature_required"},"certification_scope":{"bundled_scheme_profiles":["Visa"],"lab_supplied_scheme_profiles_required":["Mastercard"],"contactless_kernel_profile":"C-8 lab approval package","profile_material_status":"certification_format_fixture_pending_lab_signature","capk_material_status":"deterministic_public_fixture_values_must_be_replaced_by_lab_signed_capks","production_profile_bundle_required":true},"scheme_profiles":[{"scheme_name":"Visa","rid":"A000000003","kernel_type":"c8_contactless","contact_kernel_type":"legacy_visa","taa_fallback_when_offline_unable_online":"AAC","taa_no_match_default_when_online_capable":"ARQC","taa_no_match_default_when_offline_only":"AAC","aids":[{"aid":"A0000000031010","priority":1,"partial_selection":true,"interfaces":["contact","contactless"],"tac_online":"0000000000","tac_denial":"0000000000","tac_default":"0000000000","iac_online":"0000000000","iac_denial":"0000000000","iac_default":"0000000000","floor_limit":0,"cvm_limit_contact":0,"random_selection_percent":0,"contactless_transaction_limit":5000,"contactless_cvm_limit":3000,"cdcvm_supported":true,"cda_supported":true,"cda_request_encoding":"CDOL1_bit"}],"capks":[{"key_index":1,"modulus_hex":"D2E5F5B3A1C8D4E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B9C0","exponent_hex":"010001","expiry":"2030-12-31","checksum_hex":"E7BE39F210609E8609E23255BC1B54E81C7EC5D5","checksum_algorithm":"sha1(rid || key_index || modulus || exponent)","checksum_scope":["rid","key_index","modulus_hex","exponent_hex"],"source":{"owner":"scheme_or_acquirer","document":"signed_certification_capk_bundle","version":"2","verification":"external_signature_required"}}]}]}"#;
    fn certification_shaped_annex() -> String {
        include_str!("../docs/oda_test_vectors.json")
            .replace(
                "\"vector_class\": \"STRUCTURAL_FIXTURE\"",
                "\"vector_class\": \"CERTIFICATION\"",
            )
            .replace("structural fixtures", "certification vectors")
            .replace("parser and evidence plumbing", "lab acceptance")
    }

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
            KernelError::MissingMandatoryTag
        );
    }

    #[test]
    fn rejects_internal_authenticate_without_response_template() {
        assert_eq!(
            parse_internal_authenticate_response(&[
                0x9f, 0x4b, 0x08, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
            ])
            .unwrap_err(),
            KernelError::MissingMandatoryTag
        );
        assert_eq!(
            parse_internal_authenticate_response(&[
                0x77, 0x0b, 0x9f, 0x4b, 0x08, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0x9f,
                0x4c, 0x00,
            ])
            .unwrap_err(),
            KernelError::MissingMandatoryTag
        );
    }

    #[test]
    fn rejects_nested_or_duplicate_internal_authenticate_data() {
        assert_eq!(
            parse_internal_authenticate_response(&[
                0x77, 0x0d, 0xa5, 0x0b, 0x9f, 0x4b, 0x08, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
                0xa8,
            ])
            .unwrap_err(),
            KernelError::ParseError
        );

        assert_eq!(
            parse_internal_authenticate_response(&[
                0x77, 0x1d, 0x9f, 0x4b, 0x08, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0x9f,
                0x4c, 0x02, 0x01, 0x02, 0xa5, 0x0b, 0x9f, 0x4b, 0x08, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5,
                0xb6, 0xb7, 0xb8,
            ])
            .unwrap_err(),
            KernelError::ParseError
        );

        assert_eq!(
            parse_internal_authenticate_response(&[
                0x77, 0x16, 0x9f, 0x4b, 0x08, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0x9f,
                0x4b, 0x08, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,
            ])
            .unwrap_err(),
            KernelError::ParseError
        );

        assert_eq!(
            parse_internal_authenticate_response(&[
                0x77, 0x15, 0x9f, 0x4b, 0x08, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0x9f,
                0x4c, 0x02, 0x01, 0x02, 0x9f, 0x4c, 0x02, 0x03, 0x04,
            ])
            .unwrap_err(),
            KernelError::ParseError
        );
    }

    #[test]
    fn rejects_empty_internal_authenticate_icc_dynamic_number() {
        assert_eq!(
            parse_internal_authenticate_response(&[
                0x77, 0x0e, 0x9f, 0x4b, 0x08, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0x9f,
                0x4c, 0x00,
            ])
            .unwrap_err(),
            KernelError::ParseError
        );
    }

    #[test]
    fn validates_public_key_certificate_inputs_before_recovery() {
        let mut data = DataStore::new();
        data.put(
            &[0x90],
            &[
                0x6a, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                0x0f, 0xbc,
            ],
        )
        .unwrap();
        data.put(&[0x92], &[0x31, 0x32, 0x33]).unwrap();
        data.put(&[0x9f, 0x32], &[0x03]).unwrap();
        data.put(
            &[0x9f, 0x46],
            &[
                0x6a, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
                0x1e, 0xbc,
            ],
        )
        .unwrap();
        data.put(&[0x9f, 0x48], &[0x41, 0x42]).unwrap();
        data.put(&[0x9f, 0x47], &[0x01, 0x00, 0x01]).unwrap();

        let issuer = validate_issuer_public_key_inputs(&data).unwrap();
        assert_eq!(issuer.remainder, vec![0x31, 0x32, 0x33]);
        assert_eq!(issuer.exponent, vec![0x03]);

        let icc = validate_icc_public_key_inputs(&data).unwrap();
        assert_eq!(icc.remainder, vec![0x41, 0x42]);
        assert_eq!(icc.exponent, vec![0x01, 0x00, 0x01]);

        let mut missing_exponent = data.clone();
        missing_exponent.put(&[0x9f, 0x32], &[]).unwrap();
        assert_eq!(
            validate_issuer_public_key_inputs(&missing_exponent).unwrap_err(),
            KernelError::InvalidProfile
        );

        let mut truncated = data;
        truncated.put(&[0x9f, 0x46], &[0x6a, 0x01, 0x02]).unwrap();
        assert_eq!(
            validate_icc_public_key_inputs(&truncated).unwrap_err(),
            KernelError::InvalidProfile
        );
    }

    #[test]
    fn rejects_public_key_material_above_resource_limits() {
        let mut data = DataStore::new();
        data.put(
            &[0x90],
            &[
                0x6a, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                0x0f, 0xbc,
            ],
        )
        .unwrap();
        data.put(&[0x92], &vec![0x55; MAX_ODA_REMAINDER_BYTES + 1])
            .unwrap();
        data.put(&[0x9f, 0x32], &[0x03]).unwrap();

        assert_eq!(
            validate_issuer_public_key_inputs(&data).unwrap_err(),
            KernelError::InvalidProfile
        );

        let mut modulus = vec![0x80; MAX_ODA_RSA_MODULUS_BYTES + 1];
        *modulus.last_mut().unwrap() = 0x81;
        let signature = vec![0x01; modulus.len()];
        assert_eq!(
            recover_rsa_public_block(&signature, &modulus, &[0x03]).unwrap_err(),
            KernelError::InvalidProfile
        );
    }

    #[test]
    fn builds_static_authentication_data_from_afl_records_and_tag_list() {
        let mut data = DataStore::new();
        data.put(&[0x9f, 0x4a], &[0x82]).unwrap();
        data.put(&[0x82], &[0x78, 0x00]).unwrap();

        let records = [
            StaticAuthenticationRecord {
                sfi: 2,
                record: 1,
                body: decode_hex("700C5A04123456785F2403261231").unwrap(),
            },
            StaticAuthenticationRecord {
                sfi: 11,
                record: 1,
                body: decode_hex("70035F2000").unwrap(),
            },
        ];

        assert_eq!(
            build_static_authentication_data(&records, &data).unwrap(),
            decode_hex("5A04123456785F240326123170035F20007800").unwrap()
        );

        let mut missing_tag = DataStore::new();
        missing_tag.put(&[0x9f, 0x4a], &[0x82]).unwrap();
        assert_eq!(
            build_static_authentication_data(&records, &missing_tag).unwrap_err(),
            KernelError::MissingMandatoryTag
        );

        assert_eq!(
            build_static_authentication_data(
                &[StaticAuthenticationRecord {
                    sfi: 2,
                    record: 1,
                    body: decode_hex("5A0412345678").unwrap(),
                }],
                &data,
            )
            .unwrap_err(),
            KernelError::InvalidProfile
        );
    }

    #[test]
    fn rejects_malformed_static_authentication_tag_list() {
        let records = [StaticAuthenticationRecord {
            sfi: 2,
            record: 1,
            body: decode_hex("700C5A04123456785F2403261231").unwrap(),
        }];

        let mut duplicate_tag = DataStore::new();
        duplicate_tag.put(&[0x9f, 0x4a], &[0x82, 0x82]).unwrap();
        duplicate_tag.put(&[0x82], &[0x78, 0x00]).unwrap();
        assert_eq!(
            build_static_authentication_data(&records, &duplicate_tag).unwrap_err(),
            KernelError::ParseError
        );

        let mut constructed_tag = DataStore::new();
        constructed_tag.put(&[0x9f, 0x4a], &[0xa5]).unwrap();
        assert_eq!(
            build_static_authentication_data(&records, &constructed_tag).unwrap_err(),
            KernelError::ParseError
        );

        let mut zero_prefixed_high_tag = DataStore::new();
        zero_prefixed_high_tag
            .put(&[0x9f, 0x4a], &[0x9f, 0x80, 0x04])
            .unwrap();
        assert_eq!(
            build_static_authentication_data(&records, &zero_prefixed_high_tag).unwrap_err(),
            KernelError::ParseError
        );

        for tag_list in [[0x00].as_slice(), &[0xff]] {
            let mut invalid_tag = DataStore::new();
            invalid_tag.put(&[0x9f, 0x4a], tag_list).unwrap();
            assert_eq!(
                build_static_authentication_data(&records, &invalid_tag).unwrap_err(),
                KernelError::ParseError
            );
        }
    }

    #[test]
    fn rejects_static_authentication_tag_lists_above_limit() {
        let records = [StaticAuthenticationRecord {
            sfi: 2,
            record: 1,
            body: decode_hex("700C5A04123456785F2403261231").unwrap(),
        }];
        let mut data = DataStore::new();
        let tag_list: Vec<u8> = (1..=MAX_STATIC_AUTH_TAG_LIST_TAGS + 1)
            .map(|index| u8::try_from(index).unwrap())
            .collect();
        data.put(&[0x9f, 0x4a], &tag_list).unwrap();

        assert_eq!(
            build_static_authentication_data(&records, &data).unwrap_err(),
            KernelError::LengthOverflow
        );
    }

    #[test]
    fn rejects_static_authentication_data_above_aggregate_limit() {
        let records = [StaticAuthenticationRecord {
            sfi: 11,
            record: 1,
            body: vec![0xaa; MAX_ODA_AUTHENTICATION_DATA_BYTES + 1],
        }];

        assert_eq!(
            build_static_authentication_data(&records, &DataStore::new()).unwrap_err(),
            KernelError::LengthOverflow
        );
    }

    #[test]
    fn parses_recovered_public_key_certificate_material_with_remainder() {
        let recovered = decode_hex(
            "6A02\
             12345678901234567890\
             3012\
             010203\
             01\
             01\
             09\
             01\
             A1A2A3A4A5A6\
             54E3F6BE991906017C1752CD7BA97BEC321202FC\
             BC",
        )
        .unwrap();
        let certificate = parse_recovered_public_key_certificate(
            RecoveredCertificateKind::Issuer,
            &recovered,
            &[0xb1, 0xb2, 0xb3],
            &[0x03],
        )
        .unwrap();

        assert_eq!(certificate.kind, RecoveredCertificateKind::Issuer);
        assert_eq!(certificate.identifier, hex10("12345678901234567890"));
        assert_eq!(certificate.expiration_date, [0x30, 0x12]);
        assert_eq!(certificate.serial_number, [0x01, 0x02, 0x03]);
        assert_eq!(
            certificate.public_key,
            decode_hex("A1A2A3A4A5A6B1B2B3").unwrap()
        );
        assert_eq!(certificate.exponent, vec![0x03]);
        assert_eq!(
            recovered_public_key_certificate_hash_input(&certificate, &[]).unwrap(),
            decode_hex("0212345678901234567890301201020301010901A1A2A3A4A5A6B1B2B303").unwrap()
        );
        assert!(recovered_public_key_certificate_hash_is_valid(&certificate, &[]).unwrap());

        let mut tampered_key = certificate.clone();
        tampered_key.public_key[0] ^= 0x01;
        assert!(!recovered_public_key_certificate_hash_is_valid(&tampered_key, &[]).unwrap());

        let mut unsupported_hash = certificate.clone();
        unsupported_hash.hash_algorithm_indicator = 0x02;
        assert_eq!(
            recovered_public_key_certificate_hash_is_valid(&unsupported_hash, &[]).unwrap_err(),
            KernelError::InvalidProfile
        );

        let mut bad_format = recovered.clone();
        bad_format[1] = 0x04;
        assert_eq!(
            parse_recovered_public_key_certificate(
                RecoveredCertificateKind::Issuer,
                &bad_format,
                &[0xb1, 0xb2, 0xb3],
                &[0x03],
            )
            .unwrap_err(),
            KernelError::InvalidProfile
        );

        assert_eq!(
            parse_recovered_public_key_certificate(
                RecoveredCertificateKind::Issuer,
                &recovered,
                &[0xb1],
                &[0x03],
            )
            .unwrap_err(),
            KernelError::InvalidProfile
        );
    }

    #[test]
    fn recovers_rsa_public_blocks_with_bounded_modular_exponentiation() {
        assert_eq!(
            recover_rsa_public_block(
                &decode_hex("08A7").unwrap(),
                &decode_hex("0CA1").unwrap(),
                &[0x11]
            )
            .unwrap(),
            decode_hex("0042").unwrap()
        );
        assert_eq!(
            recover_rsa_public_block(
                &decode_hex("08A7").unwrap(),
                &decode_hex("0CA1").unwrap(),
                &decode_hex("010001").unwrap(),
            )
            .unwrap(),
            decode_hex("0042").unwrap()
        );
        assert_eq!(
            recover_rsa_public_block(
                &decode_hex("04AD55").unwrap(),
                &decode_hex("110011").unwrap(),
                &[0x03],
            )
            .unwrap(),
            decode_hex("003039").unwrap()
        );

        assert_eq!(
            recover_rsa_public_block(
                &decode_hex("0CA1").unwrap(),
                &decode_hex("0CA1").unwrap(),
                &[0x11]
            )
            .unwrap_err(),
            KernelError::InvalidProfile
        );
        assert_eq!(
            recover_rsa_public_block(
                &decode_hex("08A7").unwrap(),
                &decode_hex("0CA1").unwrap(),
                &[0x02]
            )
            .unwrap_err(),
            KernelError::InvalidProfile
        );
    }

    #[test]
    fn recovers_parses_and_verifies_public_key_certificates() {
        let signing_modulus = decode_hex(
            "E818096D661646F609946CBEEF726473A6639B5155FE6C9F5B5F941685E43A75\
             E896E4F401899CF2862D673A0434B6D1",
        )
        .unwrap();
        let certificate_signature = decode_hex(
            "C4D65E662B5043337656B47BF6400C1DAFBC58EAEC6FD9E2B01EB308C2CA501\
             C2538BD302ADE38BD73E2032AF4B3BB7C",
        )
        .unwrap();
        let certificate = recover_and_verify_public_key_certificate(
            RecoveredCertificateKind::Issuer,
            &certificate_signature,
            &signing_modulus,
            &decode_hex("010001").unwrap(),
            &decode_hex("B1B2B3").unwrap(),
            &[0x03],
            &[],
        )
        .unwrap();

        assert_eq!(certificate.kind, RecoveredCertificateKind::Issuer);
        assert_eq!(certificate.identifier, hex10("12345678901234567890"));
        assert_eq!(
            certificate.public_key,
            decode_hex("A1A2A3A4A5A6B1B2B3").unwrap()
        );

        assert_eq!(
            recover_and_verify_public_key_certificate(
                RecoveredCertificateKind::Issuer,
                &certificate_signature,
                &signing_modulus,
                &decode_hex("010001").unwrap(),
                &decode_hex("B1B2B3").unwrap(),
                &decode_hex("010001").unwrap(),
                &[],
            )
            .unwrap_err(),
            KernelError::InvalidProfile
        );
        assert_eq!(
            recover_and_verify_public_key_certificate(
                RecoveredCertificateKind::Icc,
                &certificate_signature,
                &signing_modulus,
                &decode_hex("010001").unwrap(),
                &decode_hex("B1B2B3").unwrap(),
                &[0x03],
                &[],
            )
            .unwrap_err(),
            KernelError::InvalidProfile
        );
    }

    #[test]
    fn recovers_parses_and_verifies_signed_application_data() {
        let static_modulus = decode_hex(
            "B0428067C589A60DDEACFDDF558479E0DB7676E1FFCEBC3B3B55657D5C4E57EA\
             B2D5592AAC2F9B767E0832C473200621",
        )
        .unwrap();
        let static_signature = decode_hex(
            "6D492A5DB481273D1127EF24D1059B5702AED358BB75A3AD004766DD75157DE9\
             9A517A830517EB821D22CD55E0FF2AE4",
        )
        .unwrap();
        let static_data = recover_and_verify_signed_application_data(
            RecoveredSignedDataKind::StaticApplicationData,
            &static_signature,
            &static_modulus,
            &decode_hex("010001").unwrap(),
            &decode_hex("AABBCC").unwrap(),
        )
        .unwrap();

        assert_eq!(static_data.data_authentication_code, Some([0x12, 0x34]));
        assert_eq!(static_data.icc_dynamic_data, None);
        assert!(static_data.padding.iter().all(|byte| *byte == 0xbb));
        assert!(recovered_signed_application_data_hash_is_valid(
            &static_data,
            &decode_hex("AABBCC").unwrap()
        )
        .unwrap());

        let dynamic_modulus = decode_hex(
            "B706C0C6940601638E89144AEC5D8C229DA65024129CD31CE56F75F4FEC42EC\
             9921572260452EC32BDC7672863BEAA53",
        )
        .unwrap();
        let dynamic_signature = decode_hex(
            "A826FBA6E8D7C0548D2E05551AFEEE0512C8AB02F33055BC389BECD93026B69F\
             B5ED72B750BE23C27E932C963F820550",
        )
        .unwrap();
        let dynamic_data = recover_and_verify_signed_application_data(
            RecoveredSignedDataKind::DynamicApplicationData,
            &dynamic_signature,
            &dynamic_modulus,
            &decode_hex("010001").unwrap(),
            &decode_hex("11223344").unwrap(),
        )
        .unwrap();

        assert_eq!(dynamic_data.data_authentication_code, None);
        assert_eq!(dynamic_data.icc_dynamic_data, Some(vec![1, 2, 3, 4]));
        assert!(recovered_signed_application_data_hash_is_valid(
            &dynamic_data,
            &decode_hex("11223344").unwrap()
        )
        .unwrap());
        assert!(!recovered_signed_application_data_hash_is_valid(&dynamic_data, &[]).unwrap());
        assert_eq!(
            recover_and_verify_signed_application_data(
                RecoveredSignedDataKind::StaticApplicationData,
                &dynamic_signature,
                &dynamic_modulus,
                &decode_hex("010001").unwrap(),
                &decode_hex("11223344").unwrap(),
            )
            .unwrap_err(),
            KernelError::InvalidProfile
        );
    }

    #[test]
    fn verifies_sda_from_issuer_key_static_records_and_signed_data() {
        let issuer_public_key = RecoveredPublicKeyCertificate {
            kind: RecoveredCertificateKind::Issuer,
            identifier: hex10("12345678901234567890"),
            expiration_date: [0x30, 0x12],
            serial_number: [0x01, 0x02, 0x03],
            hash_algorithm_indicator: 0x01,
            public_key_algorithm_indicator: 0x01,
            public_key: decode_hex(
                "B0428067C589A60DDEACFDDF558479E0DB7676E1FFCEBC3B3B55657D5C4E57EA\
                 B2D5592AAC2F9B767E0832C473200621",
            )
            .unwrap(),
            exponent: decode_hex("010001").unwrap(),
            hash_result: [0x11; SHA1_DIGEST_BYTES],
        };
        let signed_static_application_data = decode_hex(
            "6D492A5DB481273D1127EF24D1059B5702AED358BB75A3AD004766DD75157DE9\
             9A517A830517EB821D22CD55E0FF2AE4",
        )
        .unwrap();
        let mut data = DataStore::new();
        data.put(&[0x9f, 0x4a], &[0x82]).unwrap();
        data.put(&[0x82], &[0xcc]).unwrap();
        let records = [
            StaticAuthenticationRecord {
                sfi: 11,
                record: 1,
                body: decode_hex("AA").unwrap(),
            },
            StaticAuthenticationRecord {
                sfi: 12,
                record: 1,
                body: decode_hex("BB").unwrap(),
            },
        ];

        let recovered = verify_static_data_authentication(
            &issuer_public_key,
            &signed_static_application_data,
            &records,
            &data,
        )
        .unwrap();
        assert_eq!(recovered.data_authentication_code, Some([0x12, 0x34]));

        let mut wrong_key_kind = issuer_public_key.clone();
        wrong_key_kind.kind = RecoveredCertificateKind::Icc;
        assert_eq!(
            verify_static_data_authentication(
                &wrong_key_kind,
                &signed_static_application_data,
                &records,
                &data,
            )
            .unwrap_err(),
            KernelError::InvalidProfile
        );

        let mut wrong_tag_value = data;
        wrong_tag_value.put(&[0x82], &[0xdd]).unwrap();
        assert_eq!(
            verify_static_data_authentication(
                &issuer_public_key,
                &signed_static_application_data,
                &records,
                &wrong_tag_value,
            )
            .unwrap_err(),
            KernelError::InvalidProfile
        );
    }

    #[test]
    fn validates_complete_vector_syntax_and_rejects_placeholders() {
        let complete = certification_shaped_annex();
        validate_oda_vector_annex(complete.as_bytes(), true).unwrap();

        let relabeled_fixture = include_str!("../docs/oda_test_vectors.json").replace(
            "\"vector_class\": \"STRUCTURAL_FIXTURE\"",
            "\"vector_class\": \"CERTIFICATION\"",
        );
        assert_eq!(
            validate_oda_vector_annex(relabeled_fixture.as_bytes(), true).unwrap_err(),
            KernelError::InvalidProfile
        );

        let fixture = br#"{"vector_class":"STRUCTURAL_FIXTURE","test_vectors":[{"id":"SDA","capk":{"rid":"A000000003","key_index":1,"modulus_hex":"D2E5F5B3A1C8D4E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0","exponent_hex":"010001","checksum_hex":"A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8"},"issuer_certificate_hex":"6F2A9F103A1B2C3D4E5F60718293A4B5C6D7E8F9A0","static_signature_hex":"ABCD1234567890ABCD","expected_tvr":"0000000000","expected_oda_result":"PASS"}]}"#;
        validate_oda_vector_annex(fixture, false).unwrap();
        assert_eq!(
            validate_oda_vector_annex(fixture, true).unwrap_err(),
            KernelError::InvalidProfile
        );

        let sda_only = br#"{"vector_class":"CERTIFICATION","test_vectors":[{"id":"SDA","capk":{"rid":"A000000003","key_index":1,"modulus_hex":"D2E5F5B3A1C8D4E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0","exponent_hex":"010001","checksum_hex":"A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8"},"issuer_certificate_hex":"6F2A9F103A1B2C3D4E5F60718293A4B5C6D7E8F9A0","static_signature_hex":"ABCD1234567890ABCD","expected_tvr":"0000000000","expected_oda_result":"PASS"}]}"#;
        assert_eq!(
            validate_oda_vector_annex(sda_only, true).unwrap_err(),
            KernelError::InvalidProfile
        );

        let placeholder = br#"{"vector_class":"CERTIFICATION","test_vectors":[{"issuer_certificate_hex":"...","expected_tvr":"0000000000","expected_oda_result":"PASS"}]}"#;
        assert_eq!(
            validate_oda_vector_annex(placeholder, true).unwrap_err(),
            KernelError::InvalidProfile
        );
    }

    #[test]
    fn certification_vector_coverage_is_method_specific() {
        let complete = certification_shaped_annex();
        validate_oda_vector_annex(complete.as_bytes(), true).unwrap();

        let dda_auth_response =
            "      \"internal_auth_response_hex\": \"9F4C2081A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9\",\n";
        let misbound = complete.replace(dda_auth_response, "").replace(
            "      \"cda_request_bit_used\": \"CDOL1_bit\",",
            "      \"internal_auth_response_hex\": \"9F4C2081A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9\",\n      \"cda_request_bit_used\": \"CDOL1_bit\",",
        );

        assert!(
            misbound.contains("\"internal_auth_response_hex\""),
            "fixture must still contain the field globally"
        );
        assert_eq!(
            validate_oda_vector_annex(misbound.as_bytes(), true).unwrap_err(),
            KernelError::InvalidProfile
        );
    }

    #[test]
    fn oda_debug_redacts_recovered_authentication_material() {
        let internal_auth = InternalAuthenticateResponse {
            signed_dynamic_application_data: vec![0xde, 0xad, 0xbe, 0xef],
            icc_dynamic_number: Some(vec![0xaa, 0xbb]),
        };
        let public_key_input = PublicKeyInput {
            certificate: vec![0xde, 0xad, 0xbe, 0xef],
            remainder: vec![0xaa, 0xbb],
            exponent: vec![0x01, 0x00, 0x01],
        };
        let static_record = StaticAuthenticationRecord {
            sfi: 11,
            record: 1,
            body: vec![0xde, 0xad, 0xbe, 0xef],
        };
        let certificate = RecoveredPublicKeyCertificate {
            kind: RecoveredCertificateKind::Icc,
            identifier: [0xde; 10],
            expiration_date: [0x30, 0x12],
            serial_number: [0xad, 0xbe, 0xef],
            hash_algorithm_indicator: 0x01,
            public_key_algorithm_indicator: 0x01,
            public_key: vec![0xaa, 0xbb, 0xcc, 0xdd],
            exponent: vec![0x01, 0x00, 0x01],
            hash_result: [0xef; SHA1_DIGEST_BYTES],
        };
        let signed_data = RecoveredSignedApplicationData {
            kind: RecoveredSignedDataKind::DynamicApplicationData,
            hash_algorithm_indicator: 0x01,
            data_authentication_code: Some([0xde, 0xad]),
            icc_dynamic_data: Some(vec![0xbe, 0xef]),
            padding: vec![0xaa, 0xbb],
            hash_result: [0xcc; SHA1_DIGEST_BYTES],
        };

        for debug in [
            format!("{internal_auth:?}"),
            format!("{public_key_input:?}"),
            format!("{static_record:?}"),
            format!("{certificate:?}"),
            format!("{signed_data:?}"),
        ] {
            assert!(debug.contains("redacted for crash safety"));
            for raw_byte in ["222", "173", "190", "239", "170", "187", "204", "221"] {
                assert!(!debug.contains(raw_byte));
            }
        }
    }

    fn hex10(input: &str) -> [u8; 10] {
        let bytes = decode_hex(input).unwrap();
        let mut out = [0u8; 10];
        out.copy_from_slice(&bytes);
        out
    }
}
