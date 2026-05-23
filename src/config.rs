use crate::c8::{RelayResistanceFailureOutcome, RelayResistanceProfile};
use crate::dol::parse_dol;
use crate::error::{KernelError, KernelResult};
use crate::restrictions::EmvDate;
use crate::sha1::{Sha1, SHA1_DIGEST_BYTES};
use crate::taa::{ActionCodes, TaaProfile, TerminalAction};
use crate::trm::{TransactionTypeFloorLimit, TrmProfile};
use core::fmt;
use std::collections::BTreeMap;

pub const MAX_JSON_DEPTH: usize = 24;
pub const MAX_JSON_NODES: usize = 4096;
const MAX_CAPK_RSA_MODULUS_BYTES: usize = 256;
const MAX_CAPK_RSA_EXPONENT_BYTES: usize = 3;
const CAPK_CHECKSUM_ALGORITHM: &str = "sha1(rid || key_index || modulus || exponent)";
const CAPK_CHECKSUM_SCOPE: [&str; 4] = ["rid", "key_index", "modulus_hex", "exponent_hex"];
const PROFILE_SCHEMA_VERSION: &str = "1.0";
const PROFILE_STATUS_FIXTURE_PENDING: &str = "certification_format_fixture_pending_lab_signature";
const PROFILE_STATUS_LAB_SIGNED: &str = "lab_signed_certification_profile";
const CAPK_STATUS_FIXTURE_PENDING: &str =
    "deterministic_public_fixture_values_must_be_replaced_by_lab_signed_capks";
const CAPK_STATUS_LAB_SIGNED: &str = "lab_signed_capks";
const PROFILE_MATERIAL_STATUSES: [&str; 2] =
    [PROFILE_STATUS_FIXTURE_PENDING, PROFILE_STATUS_LAB_SIGNED];
const CAPK_MATERIAL_STATUSES: [&str; 2] = [CAPK_STATUS_FIXTURE_PENDING, CAPK_STATUS_LAB_SIGNED];

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

#[derive(Clone, Eq, PartialEq)]
pub struct ProfileSet {
    pub version: u64,
    pub profile_class: ProfileClass,
    pub profile_source: ProfileSource,
    pub schemes: Vec<SchemeProfile>,
}

impl fmt::Debug for ProfileSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProfileSet")
            .field("version", &self.version)
            .field("profile_class", &self.profile_class)
            .field("profile_source", &self.profile_source)
            .field("scheme_count", &self.schemes.len())
            .field(
                "data_policy",
                &"profile contents and CAPK material redacted for crash safety",
            )
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProfileClass {
    Certification,
    ExampleOnly,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileSource {
    pub owner: String,
    pub document: String,
    pub version: String,
    pub retrieved: Option<EmvDate>,
    pub verification: String,
}

struct CertificationScope {
    bundled_scheme_profiles: Vec<String>,
}

#[derive(Clone, Eq, PartialEq)]
pub struct SchemeProfile {
    pub scheme_name: String,
    pub rid: [u8; 5],
    pub kernel_type: String,
    pub contact_kernel_type: Option<String>,
    pub taa: TaaProfile,
    pub aids: Vec<AidProfile>,
    pub capks: Vec<Capk>,
}

impl fmt::Debug for SchemeProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SchemeProfile")
            .field("scheme_name", &self.scheme_name)
            .field("rid", &self.rid)
            .field("kernel_type", &self.kernel_type)
            .field("contact_kernel_type", &self.contact_kernel_type)
            .field("aid_count", &self.aids.len())
            .field("capk_count", &self.capks.len())
            .field(
                "data_policy",
                &"AID profile details and CAPK material redacted for crash safety",
            )
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AidProfile {
    pub aid: Vec<u8>,
    pub priority: u8,
    pub partial_selection: bool,
    pub interfaces: Vec<String>,
    pub action_codes: ActionCodes,
    pub issuer_action_codes: ActionCodes,
    pub floor_limit: u64,
    pub transaction_type_floor_limits: Vec<TransactionTypeFloorLimit>,
    pub cvm_limit_contact: u64,
    pub random_selection_percent: u8,
    pub lower_consecutive_offline_limit: Option<u16>,
    pub upper_consecutive_offline_limit: Option<u16>,
    pub contactless_transaction_limit: u64,
    pub contactless_cvm_limit: u64,
    pub cdcvm_supported: bool,
    pub cda_supported: bool,
    pub cda_request_encoding: Option<CdaRequestEncoding>,
    pub default_cdol1: Option<Vec<u8>>,
    pub critical_issuer_script_ins: Vec<u8>,
    pub relay_resistance: Option<RelayResistanceProfile>,
}

impl fmt::Debug for AidProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AidProfile")
            .field("aid_len", &self.aid.len())
            .field("priority", &self.priority)
            .field("partial_selection", &self.partial_selection)
            .field("interfaces", &self.interfaces)
            .field("cda_supported", &self.cda_supported)
            .field("cda_request_encoding", &self.cda_request_encoding)
            .field(
                "default_cdol1_len",
                &self.default_cdol1.as_ref().map(Vec::len),
            )
            .field("critical_issuer_script_ins_count", &self.critical_issuer_script_ins.len())
            .field("relay_resistance_present", &self.relay_resistance.is_some())
            .field(
                "transaction_type_floor_limit_count",
                &self.transaction_type_floor_limits.len(),
            )
            .field(
                "data_policy",
                &"AID values, action codes, limits, DOL bytes, and script policy bytes redacted for crash safety",
            )
            .finish()
    }
}

impl AidProfile {
    pub fn trm_profile(&self) -> Option<TrmProfile> {
        TrmProfile::with_transaction_type_floor_limits(
            self.floor_limit,
            self.transaction_type_floor_limits.clone(),
            self.random_selection_percent,
            self.lower_consecutive_offline_limit,
            self.upper_consecutive_offline_limit,
        )
    }

    pub fn cda_allowed_by_profile(&self) -> bool {
        self.cda_supported && self.cda_request_encoding.is_some()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CdaRequestEncoding {
    InCdolData,
    P1LowBits(u8),
}

#[derive(Clone, Eq, PartialEq)]
pub struct Capk {
    pub rid: [u8; 5],
    pub key_index: u8,
    pub modulus: Vec<u8>,
    pub exponent: Vec<u8>,
    pub expiry: EmvDate,
    pub checksum: Vec<u8>,
    pub source: ProfileSource,
}

impl fmt::Debug for Capk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Capk")
            .field("rid", &self.rid)
            .field("key_index", &self.key_index)
            .field("expiry", &self.expiry)
            .field("modulus_len", &self.modulus.len())
            .field("exponent_len", &self.exponent.len())
            .field("checksum_len", &self.checksum.len())
            .field("source", &self.source)
            .field(
                "data_policy",
                &"CAPK modulus, exponent, and checksum bytes redacted for crash safety",
            )
            .finish()
    }
}

pub fn load_profile_set(json: &[u8], policy: &ConfigLoadPolicy) -> KernelResult<ProfileSet> {
    if matches!(
        policy.mode,
        BuildMode::Certification | BuildMode::Production
    ) && policy.signature_status != SignatureStatus::Verified
    {
        return Err(KernelError::InvalidProfile);
    }
    if policy.candidate_version <= policy.installed_version {
        return Err(KernelError::InvalidProfile);
    }

    let root = JsonParser::new(json).parse()?;
    let object = root.as_object()?;
    reject_unknown_fields(
        object,
        &[
            "schema_version",
            "profile_class",
            "profile_source",
            "certification_scope",
            "scheme_profiles",
        ],
    )?;
    validate_profile_schema_version(object, policy.mode)?;
    let profile_class = parse_profile_class(object, policy.mode)?;
    let certification_scope = parse_certification_scope(
        object.get("certification_scope"),
        profile_class,
        policy.mode,
    )?;
    let profile_source =
        parse_profile_source(object, profile_class, policy.mode, policy.evaluation_date)?;
    let schemes_value = object
        .get("scheme_profiles")
        .ok_or(KernelError::InvalidProfile)?;
    let schemes_array = schemes_value.as_array()?;
    if schemes_array.is_empty() {
        return Err(KernelError::InvalidProfile);
    }

    let mut schemes = Vec::with_capacity(schemes_array.len());
    for scheme_value in schemes_array {
        schemes.push(parse_scheme(
            scheme_value,
            policy.evaluation_date,
            profile_class,
            policy.mode,
        )?);
    }
    reject_duplicate_scheme_rids(&schemes)?;
    validate_certification_scope_scheme_profiles(certification_scope.as_ref(), &schemes)?;
    Ok(ProfileSet {
        version: policy.candidate_version,
        profile_class,
        profile_source,
        schemes,
    })
}

fn reject_duplicate_scheme_rids(schemes: &[SchemeProfile]) -> KernelResult<()> {
    for (index, scheme) in schemes.iter().enumerate() {
        if schemes[..index].iter().any(|prior| prior.rid == scheme.rid) {
            return Err(KernelError::InvalidProfile);
        }
    }
    Ok(())
}

fn validate_certification_scope_scheme_profiles(
    scope: Option<&CertificationScope>,
    schemes: &[SchemeProfile],
) -> KernelResult<()> {
    let Some(scope) = scope else {
        return Ok(());
    };
    if scope.bundled_scheme_profiles.len() != schemes.len() {
        return Err(KernelError::InvalidProfile);
    }
    if schemes.iter().any(|scheme| {
        !scope
            .bundled_scheme_profiles
            .iter()
            .any(|bundled_scheme| bundled_scheme == &scheme.scheme_name)
    }) || scope.bundled_scheme_profiles.iter().any(|bundled_scheme| {
        !schemes
            .iter()
            .any(|scheme| &scheme.scheme_name == bundled_scheme)
    }) {
        return Err(KernelError::InvalidProfile);
    }
    Ok(())
}

fn validate_profile_schema_version(
    object: &BTreeMap<String, JsonValue>,
    mode: BuildMode,
) -> KernelResult<()> {
    let Some(value) = object.get("schema_version") else {
        return match mode {
            BuildMode::Test => Ok(()),
            BuildMode::Certification | BuildMode::Production => Err(KernelError::InvalidProfile),
        };
    };
    if value.as_string()? == PROFILE_SCHEMA_VERSION {
        Ok(())
    } else {
        Err(KernelError::InvalidProfile)
    }
}

fn parse_profile_class(
    object: &BTreeMap<String, JsonValue>,
    mode: BuildMode,
) -> KernelResult<ProfileClass> {
    let Some(value) = object.get("profile_class") else {
        return match mode {
            BuildMode::Test => Ok(ProfileClass::ExampleOnly),
            BuildMode::Certification | BuildMode::Production => Err(KernelError::InvalidProfile),
        };
    };

    match value.as_string()? {
        "CERTIFICATION" => Ok(ProfileClass::Certification),
        "EXAMPLE_ONLY" => match mode {
            BuildMode::Test => Ok(ProfileClass::ExampleOnly),
            BuildMode::Certification | BuildMode::Production => Err(KernelError::InvalidProfile),
        },
        _ => Err(KernelError::InvalidProfile),
    }
}

fn parse_profile_source(
    object: &BTreeMap<String, JsonValue>,
    profile_class: ProfileClass,
    mode: BuildMode,
    evaluation_date: EmvDate,
) -> KernelResult<ProfileSource> {
    let Some(value) = object.get("profile_source") else {
        return match (mode, profile_class) {
            (BuildMode::Test, ProfileClass::ExampleOnly) => Ok(ProfileSource {
                owner: "unspecified_test_profile".to_string(),
                document: "inline_test_fixture".to_string(),
                version: "0".to_string(),
                retrieved: None,
                verification: "test_only".to_string(),
            }),
            _ => Err(KernelError::InvalidProfile),
        };
    };
    parse_source_object(value.as_object()?, profile_class, evaluation_date)
}

fn parse_source_object(
    source: &BTreeMap<String, JsonValue>,
    profile_class: ProfileClass,
    evaluation_date: EmvDate,
) -> KernelResult<ProfileSource> {
    reject_unknown_fields(
        source,
        &["owner", "document", "version", "retrieved", "verification"],
    )?;
    let owner = required_string(source, "owner")?;
    let document = required_string(source, "document")?;
    let version = required_string(source, "version")?;
    let retrieved = optional_retrieved_date(source)?;
    let verification = required_string(source, "verification")?;

    if profile_class == ProfileClass::Certification {
        reject_placeholder(owner)?;
        reject_placeholder(document)?;
        reject_placeholder(version)?;
        reject_placeholder(verification)?;
        reject_untrimmed_or_blank(owner)?;
        reject_untrimmed_or_blank(document)?;
        reject_untrimmed_or_blank(version)?;
        let Some(retrieved) = retrieved else {
            return Err(KernelError::InvalidProfile);
        };
        if retrieved > evaluation_date {
            return Err(KernelError::InvalidProfile);
        }
        if verification != "external_signature_required" {
            return Err(KernelError::InvalidProfile);
        }
    }

    Ok(ProfileSource {
        owner: owner.to_string(),
        document: document.to_string(),
        version: version.to_string(),
        retrieved,
        verification: verification.to_string(),
    })
}

fn reject_untrimmed_or_blank(value: &str) -> KernelResult<()> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() != value.len() {
        return Err(KernelError::InvalidProfile);
    }
    Ok(())
}

fn parse_certification_scope(
    value: Option<&JsonValue>,
    profile_class: ProfileClass,
    mode: BuildMode,
) -> KernelResult<Option<CertificationScope>> {
    let Some(value) = value else {
        return match profile_class {
            ProfileClass::Certification => Err(KernelError::InvalidProfile),
            ProfileClass::ExampleOnly => Ok(None),
        };
    };
    let scope = value.as_object()?;
    reject_unknown_fields(
        scope,
        &[
            "bundled_scheme_profiles",
            "lab_supplied_scheme_profiles_required",
            "contactless_kernel_profile",
            "profile_material_status",
            "capk_material_status",
            "production_profile_bundle_required",
        ],
    )?;
    if profile_class == ProfileClass::ExampleOnly {
        return Ok(None);
    }

    let bundled = required_string_set(scope, "bundled_scheme_profiles", true)?;
    let lab_required = required_string_set(scope, "lab_supplied_scheme_profiles_required", false)?;
    if bundled.iter().any(|bundled_scheme| {
        lab_required
            .iter()
            .any(|lab_scheme| lab_scheme == bundled_scheme)
    }) {
        return Err(KernelError::InvalidProfile);
    }
    let contactless_profile = required_string(scope, "contactless_kernel_profile")?;
    reject_placeholder(contactless_profile)?;
    if contactless_profile.trim().is_empty() {
        return Err(KernelError::InvalidProfile);
    }
    let profile_material_status =
        required_allowed_string(scope, "profile_material_status", &PROFILE_MATERIAL_STATUSES)?;
    let capk_material_status =
        required_allowed_string(scope, "capk_material_status", &CAPK_MATERIAL_STATUSES)?;
    if mode == BuildMode::Production
        && (profile_material_status != PROFILE_STATUS_LAB_SIGNED
            || capk_material_status != CAPK_STATUS_LAB_SIGNED)
    {
        return Err(KernelError::InvalidProfile);
    }
    if !required_bool(scope, "production_profile_bundle_required")? {
        return Err(KernelError::InvalidProfile);
    }
    Ok(Some(CertificationScope {
        bundled_scheme_profiles: bundled,
    }))
}

fn parse_scheme(
    value: &JsonValue,
    evaluation_date: EmvDate,
    profile_class: ProfileClass,
    mode: BuildMode,
) -> KernelResult<SchemeProfile> {
    let object = value.as_object()?;
    reject_unknown_fields(
        object,
        &[
            "scheme_name",
            "rid",
            "kernel_type",
            "contact_kernel_type",
            "taa_fallback_when_offline_unable_online",
            "taa_no_match_default_when_online_capable",
            "taa_no_match_default_when_offline_only",
            "aids",
            "capks",
        ],
    )?;
    let scheme_name = required_string(object, "scheme_name")?;
    reject_placeholder(scheme_name)?;
    if scheme_name.trim().is_empty() {
        return Err(KernelError::InvalidProfile);
    }
    let rid_vec = parse_hex_field(object, "rid")?;
    let rid = fixed_vec::<5>(rid_vec)?;
    reject_dummy_bytes(&rid)?;
    let kernel_type = required_string(object, "kernel_type")?.to_string();
    let contact_kernel_type = parse_contact_kernel_type(object)?;

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
    reject_aids_outside_scheme_rid(&rid, &aids)?;
    reject_duplicate_aids(&aids)?;
    validate_scheme_interface_kernel_mapping(
        &kernel_type,
        contact_kernel_type.as_deref(),
        &aids,
        profile_class,
        mode,
    )?;

    let capks_value = object.get("capks").ok_or(KernelError::InvalidProfile)?;
    let capks_array = capks_value.as_array()?;
    if capks_array.is_empty() {
        return Err(KernelError::InvalidProfile);
    }
    let mut capks = Vec::with_capacity(capks_array.len());
    for capk_value in capks_array {
        capks.push(parse_capk(
            capk_value,
            rid,
            evaluation_date,
            profile_class,
            mode,
        )?);
    }
    reject_duplicate_capk_identities(&capks)?;

    Ok(SchemeProfile {
        scheme_name: scheme_name.to_string(),
        rid,
        kernel_type,
        contact_kernel_type,
        taa,
        aids,
        capks,
    })
}

fn reject_aids_outside_scheme_rid(rid: &[u8; 5], aids: &[AidProfile]) -> KernelResult<()> {
    if aids.iter().any(|aid| !aid.aid.starts_with(rid)) {
        return Err(KernelError::InvalidProfile);
    }
    Ok(())
}

fn reject_duplicate_aids(aids: &[AidProfile]) -> KernelResult<()> {
    for (index, aid) in aids.iter().enumerate() {
        if aids[..index].iter().any(|prior| prior.aid == aid.aid) {
            return Err(KernelError::InvalidProfile);
        }
    }
    Ok(())
}

fn validate_scheme_interface_kernel_mapping(
    kernel_type: &str,
    contact_kernel_type: Option<&str>,
    aids: &[AidProfile],
    profile_class: ProfileClass,
    mode: BuildMode,
) -> KernelResult<()> {
    if mode == BuildMode::Test && profile_class == ProfileClass::ExampleOnly {
        return Ok(());
    }
    reject_placeholder(kernel_type)?;
    if kernel_type.trim().is_empty() {
        return Err(KernelError::InvalidProfile);
    }

    let has_contactless = aids.iter().any(|aid| {
        aid.interfaces
            .iter()
            .any(|interface| interface == "contactless")
    });
    if has_contactless && kernel_type != "c8_contactless" {
        return Err(KernelError::InvalidProfile);
    }

    let has_contact = aids.iter().any(|aid| {
        aid.interfaces
            .iter()
            .any(|interface| interface == "contact")
    });
    if has_contact && contact_kernel_type.is_none() {
        return Err(KernelError::InvalidProfile);
    }
    Ok(())
}

fn reject_duplicate_capk_identities(capks: &[Capk]) -> KernelResult<()> {
    for (index, capk) in capks.iter().enumerate() {
        if capks[..index]
            .iter()
            .any(|prior| prior.rid == capk.rid && prior.key_index == capk.key_index)
        {
            return Err(KernelError::InvalidProfile);
        }
    }
    Ok(())
}

fn parse_contact_kernel_type(object: &BTreeMap<String, JsonValue>) -> KernelResult<Option<String>> {
    let Some(value) = object.get("contact_kernel_type") else {
        return Ok(None);
    };
    let contact_kernel_type = value.as_string()?;
    reject_placeholder(contact_kernel_type)?;
    if contact_kernel_type.trim().is_empty() || contact_kernel_type == "c8_contactless" {
        return Err(KernelError::InvalidProfile);
    }
    Ok(Some(contact_kernel_type.to_string()))
}

fn parse_aid(value: &JsonValue) -> KernelResult<AidProfile> {
    let object = value.as_object()?;
    reject_unknown_fields(
        object,
        &[
            "aid",
            "priority",
            "partial_selection",
            "interfaces",
            "tac_online",
            "tac_denial",
            "tac_default",
            "iac_online",
            "iac_denial",
            "iac_default",
            "floor_limit",
            "transaction_type_floor_limits",
            "cvm_limit_contact",
            "random_selection_percent",
            "lower_consecutive_offline_limit",
            "upper_consecutive_offline_limit",
            "contactless_transaction_limit",
            "contactless_cvm_limit",
            "cdcvm_supported",
            "cda_supported",
            "cda_request_encoding",
            "default_cdol1",
            "critical_issuer_script_ins",
            "relay_resistance",
        ],
    )?;
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
    for (index, interface) in interfaces.iter().enumerate() {
        if interfaces[..index].iter().any(|prior| prior == interface) {
            return Err(KernelError::InvalidProfile);
        }
    }

    let random_selection_percent = required_u64(object, "random_selection_percent")?;
    if random_selection_percent > 100 {
        return Err(KernelError::InvalidProfile);
    }

    let lower_consecutive_offline_limit = optional_u16(object, "lower_consecutive_offline_limit")?;
    let upper_consecutive_offline_limit = optional_u16(object, "upper_consecutive_offline_limit")?;
    if let (Some(lower), Some(upper)) = (
        lower_consecutive_offline_limit,
        upper_consecutive_offline_limit,
    ) {
        if lower > upper {
            return Err(KernelError::InvalidProfile);
        }
    }

    let contactless_transaction_limit = required_u64(object, "contactless_transaction_limit")?;
    let contactless_cvm_limit = required_u64(object, "contactless_cvm_limit")?;
    if contactless_transaction_limit != 0 && contactless_cvm_limit > contactless_transaction_limit {
        return Err(KernelError::InvalidProfile);
    }
    let cda_supported = required_bool(object, "cda_supported")?;
    let cda_request_encoding = object
        .get("cda_request_encoding")
        .and_then(JsonValue::as_string_opt)
        .map(parse_cda_request_encoding)
        .transpose()?;
    if cda_supported != cda_request_encoding.is_some() {
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
        issuer_action_codes: ActionCodes {
            online: fixed_vec::<5>(parse_hex_field(object, "iac_online")?)?,
            denial: fixed_vec::<5>(parse_hex_field(object, "iac_denial")?)?,
            default: fixed_vec::<5>(parse_hex_field(object, "iac_default")?)?,
        },
        floor_limit: required_u64(object, "floor_limit")?,
        transaction_type_floor_limits: parse_transaction_type_floor_limits(object)?,
        cvm_limit_contact: required_u64(object, "cvm_limit_contact")?,
        random_selection_percent: random_selection_percent as u8,
        lower_consecutive_offline_limit,
        upper_consecutive_offline_limit,
        contactless_transaction_limit,
        contactless_cvm_limit,
        cdcvm_supported: required_bool(object, "cdcvm_supported")?,
        cda_supported,
        cda_request_encoding,
        default_cdol1: parse_default_cdol1(object)?,
        critical_issuer_script_ins: optional_hex_byte_array(object, "critical_issuer_script_ins")?,
        relay_resistance: parse_relay_resistance_profile(object)?,
    })
}

fn parse_transaction_type_floor_limits(
    object: &BTreeMap<String, JsonValue>,
) -> KernelResult<Vec<TransactionTypeFloorLimit>> {
    let Some(value) = object.get("transaction_type_floor_limits") else {
        return Ok(Vec::new());
    };
    let values = value
        .as_array()?
        .iter()
        .map(|item| {
            let entry = item.as_object()?;
            reject_unknown_fields(entry, &["transaction_type", "floor_limit"])?;
            let transaction_type = parse_hex_field(entry, "transaction_type")?;
            if transaction_type.len() != 1 {
                return Err(KernelError::InvalidProfile);
            }
            Ok(TransactionTypeFloorLimit {
                transaction_type: transaction_type[0],
                floor_limit: required_u64(entry, "floor_limit")?,
            })
        })
        .collect::<KernelResult<Vec<_>>>()?;
    TrmProfile::with_transaction_type_floor_limits(0, values.clone(), 0, None, None)
        .ok_or(KernelError::InvalidProfile)?;
    Ok(values)
}

fn parse_default_cdol1(object: &BTreeMap<String, JsonValue>) -> KernelResult<Option<Vec<u8>>> {
    let Some(value) = object.get("default_cdol1") else {
        return Ok(None);
    };
    let cdol = value.as_string()?;
    reject_placeholder(cdol)?;
    let bytes = decode_hex(cdol)?;
    parse_dol(&bytes)?;
    Ok(Some(bytes))
}

fn parse_relay_resistance_profile(
    object: &BTreeMap<String, JsonValue>,
) -> KernelResult<Option<RelayResistanceProfile>> {
    let Some(value) = object.get("relay_resistance") else {
        return Ok(None);
    };
    let relay = value.as_object()?;
    reject_unknown_fields(
        relay,
        &[
            "required",
            "command_apdu_hex",
            "max_round_trip_ms",
            "success_response_hex",
            "failure_outcome",
        ],
    )?;
    if !required_bool(relay, "required")? {
        return Ok(None);
    }
    let max_round_trip_ms = required_u64(relay, "max_round_trip_ms")?;
    if max_round_trip_ms > u16::MAX as u64 {
        return Err(KernelError::InvalidProfile);
    }
    RelayResistanceProfile::new(
        parse_hex_field(relay, "command_apdu_hex")?,
        max_round_trip_ms as u16,
        parse_hex_field(relay, "success_response_hex")?,
        parse_relay_resistance_failure_outcome(required_string(relay, "failure_outcome")?)?,
    )
    .map(Some)
}

fn parse_relay_resistance_failure_outcome(
    input: &str,
) -> KernelResult<RelayResistanceFailureOutcome> {
    match input {
        "try_again" => Ok(RelayResistanceFailureOutcome::TryAgain),
        "alternate_interface" => Ok(RelayResistanceFailureOutcome::AlternateInterface),
        "terminate" => Ok(RelayResistanceFailureOutcome::Terminate),
        _ => Err(KernelError::InvalidProfile),
    }
}

fn parse_cda_request_encoding(input: &str) -> KernelResult<CdaRequestEncoding> {
    if input == "CDOL1_bit" {
        return Ok(CdaRequestEncoding::InCdolData);
    }
    let Some(hex) = input.strip_prefix("P1_low_bits_0x") else {
        return Err(KernelError::InvalidProfile);
    };
    if hex.len() != 2 {
        return Err(KernelError::InvalidProfile);
    }
    let bits = decode_hex(hex)?
        .into_iter()
        .next()
        .ok_or(KernelError::InvalidProfile)?;
    if bits == 0 || bits & 0xc0 != 0 {
        return Err(KernelError::InvalidProfile);
    }
    Ok(CdaRequestEncoding::P1LowBits(bits))
}

fn parse_capk(
    value: &JsonValue,
    rid: [u8; 5],
    evaluation_date: EmvDate,
    profile_class: ProfileClass,
    mode: BuildMode,
) -> KernelResult<Capk> {
    let object = value.as_object()?;
    reject_unknown_fields(
        object,
        &[
            "key_index",
            "modulus_hex",
            "exponent_hex",
            "expiry",
            "checksum_hex",
            "checksum_algorithm",
            "checksum_scope",
            "source",
        ],
    )?;
    let key_index = required_u64(object, "key_index")?;
    if key_index > u8::MAX as u64 {
        return Err(KernelError::InvalidProfile);
    }
    let modulus = parse_hex_field(object, "modulus_hex")?;
    let exponent = parse_hex_field(object, "exponent_hex")?;
    let checksum = parse_hex_field(object, "checksum_hex")?;
    if checksum.len() < 16 {
        return Err(KernelError::InvalidProfile);
    }
    validate_capk_public_key_components(&modulus, &exponent)?;
    reject_dummy_bytes(&checksum)?;

    if profile_class == ProfileClass::Certification {
        validate_capk_checksum_metadata(object)?;
        if checksum.len() != SHA1_DIGEST_BYTES
            || checksum
                != capk_checksum_components(&rid, key_index as u8, &modulus, &exponent).as_slice()
        {
            return Err(KernelError::InvalidProfile);
        }
    }

    let expiry = parse_iso_date(required_string(object, "expiry")?)?;
    if expiry < evaluation_date {
        return Err(KernelError::InvalidProfile);
    }
    let source = match object.get("source") {
        Some(value) => parse_source_object(value.as_object()?, profile_class, evaluation_date)?,
        None => match (mode, profile_class) {
            (BuildMode::Test, ProfileClass::ExampleOnly) => ProfileSource {
                owner: "unspecified_test_capk".to_string(),
                document: "inline_test_fixture".to_string(),
                version: "0".to_string(),
                retrieved: None,
                verification: "test_only".to_string(),
            },
            _ => return Err(KernelError::InvalidProfile),
        },
    };

    Ok(Capk {
        rid,
        key_index: key_index as u8,
        modulus,
        exponent,
        expiry,
        checksum,
        source,
    })
}

pub(crate) fn capk_checksum_components(
    rid: &[u8; 5],
    key_index: u8,
    modulus: &[u8],
    exponent: &[u8],
) -> [u8; SHA1_DIGEST_BYTES] {
    let mut sha1 = Sha1::new();
    sha1.update(rid);
    sha1.update(&[key_index]);
    sha1.update(modulus);
    sha1.update(exponent);
    sha1.finalize()
}

fn validate_capk_checksum_metadata(object: &BTreeMap<String, JsonValue>) -> KernelResult<()> {
    if required_string(object, "checksum_algorithm")? != CAPK_CHECKSUM_ALGORITHM {
        return Err(KernelError::InvalidProfile);
    }
    let scope = object
        .get("checksum_scope")
        .ok_or(KernelError::InvalidProfile)?
        .as_array()?;
    if scope.len() != CAPK_CHECKSUM_SCOPE.len() {
        return Err(KernelError::InvalidProfile);
    }
    for (actual, expected) in scope.iter().zip(CAPK_CHECKSUM_SCOPE) {
        if actual.as_string()? != expected {
            return Err(KernelError::InvalidProfile);
        }
    }
    Ok(())
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
    EmvDate::new(year, month, day)
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

fn required_allowed_string<'a>(
    object: &'a BTreeMap<String, JsonValue>,
    key: &str,
    allowed: &[&str],
) -> KernelResult<&'a str> {
    let value = required_string(object, key)?;
    if allowed.contains(&value) {
        Ok(value)
    } else {
        Err(KernelError::InvalidProfile)
    }
}

fn required_string_set(
    object: &BTreeMap<String, JsonValue>,
    key: &str,
    must_be_non_empty: bool,
) -> KernelResult<Vec<String>> {
    let values = object
        .get(key)
        .ok_or(KernelError::InvalidProfile)?
        .as_array()?
        .iter()
        .map(|item| {
            let value = item.as_string()?;
            reject_placeholder(value)?;
            let value = value.trim();
            if value.is_empty() {
                return Err(KernelError::InvalidProfile);
            }
            Ok(value.to_string())
        })
        .collect::<KernelResult<Vec<_>>>()?;
    if must_be_non_empty && values.is_empty() {
        return Err(KernelError::InvalidProfile);
    }
    for (index, value) in values.iter().enumerate() {
        if values[..index].iter().any(|prior| prior == value) {
            return Err(KernelError::InvalidProfile);
        }
    }
    Ok(values)
}

fn required_u64(object: &BTreeMap<String, JsonValue>, key: &str) -> KernelResult<u64> {
    object.get(key).ok_or(KernelError::InvalidProfile)?.as_u64()
}

fn optional_u16(object: &BTreeMap<String, JsonValue>, key: &str) -> KernelResult<Option<u16>> {
    let Some(value) = object.get(key) else {
        return Ok(None);
    };
    let value = value.as_u64()?;
    if value > u16::MAX as u64 {
        return Err(KernelError::InvalidProfile);
    }
    Ok(Some(value as u16))
}

fn optional_retrieved_date(object: &BTreeMap<String, JsonValue>) -> KernelResult<Option<EmvDate>> {
    let Some(value) = object.get("retrieved") else {
        return Ok(None);
    };
    let retrieved = value.as_string()?;
    reject_placeholder(retrieved)?;
    if retrieved.trim().is_empty() {
        return Err(KernelError::InvalidProfile);
    }
    parse_iso_date(retrieved).map(Some)
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
        .collect::<KernelResult<Vec<_>>>()
        .and_then(|values| {
            reject_duplicate_bytes(&values)?;
            Ok(values)
        })
}

fn reject_duplicate_bytes(values: &[u8]) -> KernelResult<()> {
    for (index, value) in values.iter().enumerate() {
        if values[..index].iter().any(|prior| prior == value) {
            return Err(KernelError::InvalidProfile);
        }
    }
    Ok(())
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
    if is_dummy_bytes(value) {
        return Err(KernelError::InvalidProfile);
    }
    Ok(())
}

fn is_dummy_bytes(value: &[u8]) -> bool {
    value.iter().all(|byte| *byte == 0) || value.iter().all(|byte| *byte == 0xff)
}

fn validate_capk_public_key_components(modulus: &[u8], exponent: &[u8]) -> KernelResult<()> {
    if modulus.len() < 64
        || modulus.len() > MAX_CAPK_RSA_MODULUS_BYTES
        || modulus[0] == 0
        || is_dummy_bytes(modulus)
    {
        return Err(KernelError::InvalidProfile);
    }

    if exponent.is_empty()
        || exponent.len() > MAX_CAPK_RSA_EXPONENT_BYTES
        || exponent[0] == 0
        || is_dummy_bytes(exponent)
    {
        return Err(KernelError::InvalidProfile);
    }
    let mut value = 0u32;
    for byte in exponent {
        value = (value << 8) | u32::from(*byte);
    }
    if value < 3 || value % 2 == 0 {
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

fn reject_unknown_fields(
    object: &BTreeMap<String, JsonValue>,
    allowed: &[&str],
) -> KernelResult<()> {
    if object
        .keys()
        .any(|key| !allowed.iter().any(|allowed_key| key == allowed_key))
    {
        return Err(KernelError::InvalidProfile);
    }
    Ok(())
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
        if digits.len() > 1 && digits.starts_with('0') {
            return Err(KernelError::ParseError);
        }
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
    use crate::trm::MAX_TRANSACTION_TYPE_FLOOR_LIMITS;

    const VALID_PROFILE: &[u8] = br#"{
      "schema_version": "1.0",
      "profile_class": "CERTIFICATION",
      "profile_source": {
        "owner": "scheme_or_acquirer",
        "document": "signed_certification_profile_bundle",
        "version": "2",
        "retrieved": "2026-05-21",
        "verification": "external_signature_required"
      },
      "certification_scope": {
        "bundled_scheme_profiles": ["Visa"],
        "lab_supplied_scheme_profiles_required": ["Mastercard"],
        "contactless_kernel_profile": "C-8 lab approval package",
        "profile_material_status": "certification_format_fixture_pending_lab_signature",
        "capk_material_status": "deterministic_public_fixture_values_must_be_replaced_by_lab_signed_capks",
        "production_profile_bundle_required": true
      },
      "scheme_profiles": [{
        "scheme_name": "Visa",
        "rid": "A000000003",
        "kernel_type": "c8_contactless",
        "contact_kernel_type": "legacy_visa",
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
          "transaction_type_floor_limits": [
            {"transaction_type": "01", "floor_limit": 10000}
          ],
          "cvm_limit_contact": 5000,
          "random_selection_percent": 5,
          "contactless_transaction_limit": 5000,
          "contactless_cvm_limit": 3000,
          "cdcvm_supported": true,
          "cda_supported": true,
          "cda_request_encoding": "CDOL1_bit",
          "default_cdol1": "9F370495059F02069A039C019F1A029F3403",
          "critical_issuer_script_ins": ["E2"]
        }],
        "capks": [{
          "key_index": 1,
          "modulus_hex": "D2E5F5B3A1C8D4E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B9C0",
          "exponent_hex": "010001",
          "expiry": "2030-12-31",
          "checksum_hex": "E7BE39F210609E8609E23255BC1B54E81C7EC5D5",
          "checksum_algorithm": "sha1(rid || key_index || modulus || exponent)",
          "checksum_scope": ["rid", "key_index", "modulus_hex", "exponent_hex"],
          "source": {
            "owner": "scheme_or_acquirer",
            "document": "signed_certification_capk_bundle",
            "version": "2",
            "retrieved": "2026-05-21",
            "verification": "external_signature_required"
          }
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

    fn duplicate_first_array_object(profile: &str, array_name: &str) -> String {
        let marker = format!(r#""{array_name}": ["#);
        let array_start = profile.find(&marker).expect("profile array exists") + marker.len();
        let object_start = array_start
            + profile[array_start..]
                .find('{')
                .expect("array object exists");
        let mut depth = 0usize;
        let mut object_end = None;
        for (offset, byte) in profile[object_start..].bytes().enumerate() {
            match byte {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        object_end = Some(object_start + offset + 1);
                        break;
                    }
                }
                _ => {}
            }
        }
        let object_end = object_end.expect("array object closes");
        let object = &profile[object_start..object_end];
        let mut duplicated = String::with_capacity(profile.len() + object.len() + 2);
        duplicated.push_str(&profile[..object_end]);
        duplicated.push_str(", ");
        duplicated.push_str(object);
        duplicated.push_str(&profile[object_end..]);
        duplicated
    }

    fn hex_upper(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push_str(&format!("{byte:02X}"));
        }
        out
    }

    fn profile_with_capk_exponent(exponent_hex: &str) -> String {
        let profile = std::str::from_utf8(VALID_PROFILE).unwrap();
        let modulus = decode_hex(
            "D2E5F5B3A1C8D4E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B9C0",
        )
        .unwrap();
        let exponent = decode_hex(exponent_hex).unwrap();
        let checksum =
            capk_checksum_components(&[0xa0, 0x00, 0x00, 0x00, 0x03], 1, &modulus, &exponent);
        profile
            .replace(
                r#""exponent_hex": "010001""#,
                &format!(r#""exponent_hex": "{exponent_hex}""#),
            )
            .replace(
                r#""checksum_hex": "E7BE39F210609E8609E23255BC1B54E81C7EC5D5""#,
                &format!(r#""checksum_hex": "{}""#, hex_upper(&checksum)),
            )
    }

    #[test]
    fn loads_profile_annex_when_signature_is_verified() {
        let profiles = load_profile_set(VALID_PROFILE, &policy(SignatureStatus::Verified)).unwrap();

        assert_eq!(profiles.schemes.len(), 1);
        assert_eq!(profiles.profile_class, ProfileClass::Certification);
        assert_eq!(
            profiles.profile_source.document,
            "signed_certification_profile_bundle"
        );
        assert_eq!(profiles.schemes[0].rid, [0xa0, 0x00, 0x00, 0x00, 0x03]);
        assert_eq!(
            profiles.schemes[0].contact_kernel_type.as_deref(),
            Some("legacy_visa")
        );
        assert_eq!(
            profiles.schemes[0].aids[0].action_codes.online,
            [0xe0, 0xf8, 0xc8, 0, 0]
        );
        assert_eq!(
            profiles.schemes[0].aids[0].issuer_action_codes.default,
            [0, 0, 0, 0, 0]
        );
        assert_eq!(
            profiles.schemes[0].aids[0].default_cdol1.as_deref(),
            Some(
                &[
                    0x9f, 0x37, 0x04, 0x95, 0x05, 0x9f, 0x02, 0x06, 0x9a, 0x03, 0x9c, 0x01, 0x9f,
                    0x1a, 0x02, 0x9f, 0x34, 0x03
                ][..]
            )
        );
        assert_eq!(profiles.schemes[0].capks[0].key_index, 1);
        assert!(profiles.schemes[0].capks[0].modulus.len() >= 64);
        assert_eq!(
            profiles.schemes[0].capks[0].source.document,
            "signed_certification_capk_bundle"
        );
        assert_eq!(
            profiles.schemes[0].capks[0].source.verification,
            "external_signature_required"
        );
        assert_eq!(
            profiles.schemes[0].aids[0].critical_issuer_script_ins,
            [0xe2]
        );
        assert_eq!(
            profiles.schemes[0].aids[0].transaction_type_floor_limits,
            [TransactionTypeFloorLimit {
                transaction_type: 0x01,
                floor_limit: 10_000
            }]
        );
        assert_eq!(
            profiles.schemes[0].aids[0]
                .trm_profile()
                .unwrap()
                .floor_limit_for_transaction_type(0x01),
            10_000
        );
        assert_eq!(
            profiles.schemes[0].aids[0]
                .trm_profile()
                .unwrap()
                .floor_limit_for_transaction_type(0x00),
            0
        );
        assert_eq!(
            profiles.schemes[0].aids[0].cda_request_encoding,
            Some(CdaRequestEncoding::InCdolData)
        );
        assert!(profiles.schemes[0].aids[0].cda_allowed_by_profile());
    }

    #[test]
    fn rejects_invalid_certification_scope_boundaries() {
        let profile = std::str::from_utf8(VALID_PROFILE).unwrap();

        let missing_scope = profile.replace(
            r#",
      "certification_scope": {
        "bundled_scheme_profiles": ["Visa"],
        "lab_supplied_scheme_profiles_required": ["Mastercard"],
        "contactless_kernel_profile": "C-8 lab approval package",
        "profile_material_status": "certification_format_fixture_pending_lab_signature",
        "capk_material_status": "deterministic_public_fixture_values_must_be_replaced_by_lab_signed_capks",
        "production_profile_bundle_required": true
      }"#,
            "",
        );
        assert_eq!(
            load_profile_set(missing_scope.as_bytes(), &policy(SignatureStatus::Verified))
                .unwrap_err(),
            KernelError::InvalidProfile
        );

        let overlap = profile.replace(
            r#""lab_supplied_scheme_profiles_required": ["Mastercard"]"#,
            r#""lab_supplied_scheme_profiles_required": ["Visa"]"#,
        );
        assert_eq!(
            load_profile_set(overlap.as_bytes(), &policy(SignatureStatus::Verified)).unwrap_err(),
            KernelError::InvalidProfile
        );

        let undeclared_loaded_scheme =
            profile.replace(r#""scheme_name": "Visa""#, r#""scheme_name": "Mastercard""#);
        assert_eq!(
            load_profile_set(
                undeclared_loaded_scheme.as_bytes(),
                &policy(SignatureStatus::Verified)
            )
            .unwrap_err(),
            KernelError::InvalidProfile
        );

        let unloaded_bundled_scheme = profile.replace(
            r#""bundled_scheme_profiles": ["Visa"]"#,
            r#""bundled_scheme_profiles": ["Visa", "Discover"]"#,
        );
        assert_eq!(
            load_profile_set(
                unloaded_bundled_scheme.as_bytes(),
                &policy(SignatureStatus::Verified)
            )
            .unwrap_err(),
            KernelError::InvalidProfile
        );

        let whitespace_padded_overlap = profile.replace(
            r#""lab_supplied_scheme_profiles_required": ["Mastercard"]"#,
            r#""lab_supplied_scheme_profiles_required": [" Visa "]"#,
        );
        assert_eq!(
            load_profile_set(
                whitespace_padded_overlap.as_bytes(),
                &policy(SignatureStatus::Verified)
            )
            .unwrap_err(),
            KernelError::InvalidProfile
        );

        let whitespace_padded_duplicate = profile.replace(
            r#""bundled_scheme_profiles": ["Visa"]"#,
            r#""bundled_scheme_profiles": ["Visa", " Visa "]"#,
        );
        assert_eq!(
            load_profile_set(
                whitespace_padded_duplicate.as_bytes(),
                &policy(SignatureStatus::Verified)
            )
            .unwrap_err(),
            KernelError::InvalidProfile
        );

        let blank_bundled_scheme = profile.replace(
            r#""bundled_scheme_profiles": ["Visa"]"#,
            r#""bundled_scheme_profiles": ["   "]"#,
        );
        assert_eq!(
            load_profile_set(
                blank_bundled_scheme.as_bytes(),
                &policy(SignatureStatus::Verified)
            )
            .unwrap_err(),
            KernelError::InvalidProfile
        );

        let blank_lab_required_scheme = profile.replace(
            r#""lab_supplied_scheme_profiles_required": ["Mastercard"]"#,
            r#""lab_supplied_scheme_profiles_required": ["   "]"#,
        );
        assert_eq!(
            load_profile_set(
                blank_lab_required_scheme.as_bytes(),
                &policy(SignatureStatus::Verified)
            )
            .unwrap_err(),
            KernelError::InvalidProfile
        );

        let blank_contactless_profile = profile.replace(
            r#""contactless_kernel_profile": "C-8 lab approval package""#,
            r#""contactless_kernel_profile": "   ""#,
        );
        assert_eq!(
            load_profile_set(
                blank_contactless_profile.as_bytes(),
                &policy(SignatureStatus::Verified)
            )
            .unwrap_err(),
            KernelError::InvalidProfile
        );

        let false_production_bundle = profile.replace(
            r#""production_profile_bundle_required": true"#,
            r#""production_profile_bundle_required": false"#,
        );
        assert_eq!(
            load_profile_set(
                false_production_bundle.as_bytes(),
                &policy(SignatureStatus::Verified)
            )
            .unwrap_err(),
            KernelError::InvalidProfile
        );

        let unsupported_status = profile.replace(
            r#""profile_material_status": "certification_format_fixture_pending_lab_signature""#,
            r#""profile_material_status": "self_attested_ready_for_certification""#,
        );
        assert_eq!(
            load_profile_set(
                unsupported_status.as_bytes(),
                &policy(SignatureStatus::Verified)
            )
            .unwrap_err(),
            KernelError::InvalidProfile
        );
    }

    #[test]
    fn production_rejects_fixture_pending_profile_material() {
        let profile = std::str::from_utf8(VALID_PROFILE).unwrap();
        let production = ConfigLoadPolicy {
            mode: BuildMode::Production,
            ..policy(SignatureStatus::Verified)
        };
        assert_eq!(
            load_profile_set(profile.as_bytes(), &production).unwrap_err(),
            KernelError::InvalidProfile
        );

        let lab_signed_profile_only = profile.replace(
            r#""profile_material_status": "certification_format_fixture_pending_lab_signature""#,
            r#""profile_material_status": "lab_signed_certification_profile""#,
        );
        assert_eq!(
            load_profile_set(lab_signed_profile_only.as_bytes(), &production).unwrap_err(),
            KernelError::InvalidProfile
        );

        let lab_signed = lab_signed_profile_only.replace(
            r#""capk_material_status": "deterministic_public_fixture_values_must_be_replaced_by_lab_signed_capks""#,
            r#""capk_material_status": "lab_signed_capks""#,
        );
        let profiles = load_profile_set(lab_signed.as_bytes(), &production).unwrap();
        assert_eq!(profiles.profile_class, ProfileClass::Certification);
    }

    #[test]
    fn profile_debug_redacts_capk_and_profile_material() {
        let profiles = load_profile_set(VALID_PROFILE, &policy(SignatureStatus::Verified)).unwrap();
        let scheme = &profiles.schemes[0];
        let aid = &scheme.aids[0];
        let capk = &scheme.capks[0];

        for debug in [
            format!("{profiles:?}"),
            format!("{scheme:?}"),
            format!("{aid:?}"),
            format!("{capk:?}"),
        ] {
            assert!(debug.contains("redacted for crash safety"));
            assert!(!debug.contains("modulus:"));
            assert!(!debug.contains("exponent:"));
            assert!(!debug.contains("checksum:"));
            assert!(!debug.contains("action_codes"));
            assert!(!debug.contains("default_cdol1:"));
            for raw_byte in ["210", "229", "245", "179", "225", "167", "184", "201"] {
                assert!(!debug.contains(raw_byte));
            }
        }
    }

    #[test]
    fn parses_profile_defined_relay_resistance_policy() {
        let profile = std::str::from_utf8(VALID_PROFILE).unwrap().replace(
            r#""critical_issuer_script_ins": ["E2"]"#,
            r#""critical_issuer_script_ins": ["E2"],
          "relay_resistance": {
            "required": true,
            "command_apdu_hex": "80CA9F7A00",
            "max_round_trip_ms": 50,
            "success_response_hex": "9000",
            "failure_outcome": "try_again"
          }"#,
        );
        let profiles =
            load_profile_set(profile.as_bytes(), &policy(SignatureStatus::Verified)).unwrap();
        let relay = profiles.schemes[0].aids[0]
            .relay_resistance
            .as_ref()
            .unwrap();
        assert_eq!(relay.command_apdu, decode_hex("80CA9F7A00").unwrap());
        assert_eq!(relay.max_round_trip_ms, 50);
        assert_eq!(relay.success_response, decode_hex("9000").unwrap());
        assert_eq!(
            relay.failure_outcome,
            RelayResistanceFailureOutcome::TryAgain
        );

        let missing_command = profile.replace(r#""command_apdu_hex": "80CA9F7A00","#, "");
        assert_eq!(
            load_profile_set(
                missing_command.as_bytes(),
                &policy(SignatureStatus::Verified)
            )
            .unwrap_err(),
            KernelError::InvalidProfile
        );
    }

    #[test]
    fn loads_profile_issuer_action_code_fallbacks() {
        let profile = std::str::from_utf8(VALID_PROFILE).unwrap().replace(
            r#""iac_default": "0000000000""#,
            r#""iac_default": "2000000000""#,
        );

        let profiles =
            load_profile_set(profile.as_bytes(), &policy(SignatureStatus::Verified)).unwrap();
        assert_eq!(
            profiles.schemes[0].aids[0].issuer_action_codes.default,
            [0x20, 0, 0, 0, 0]
        );
    }

    #[test]
    fn rejects_duplicate_profile_aids_and_capk_indexes() {
        let profile = std::str::from_utf8(VALID_PROFILE).unwrap();

        let duplicate_aid = duplicate_first_array_object(profile, "aids");
        assert_eq!(
            load_profile_set(duplicate_aid.as_bytes(), &policy(SignatureStatus::Verified))
                .unwrap_err(),
            KernelError::InvalidProfile
        );

        let duplicate_capk = duplicate_first_array_object(profile, "capks");
        assert_eq!(
            load_profile_set(
                duplicate_capk.as_bytes(),
                &policy(SignatureStatus::Verified)
            )
            .unwrap_err(),
            KernelError::InvalidProfile
        );
    }

    #[test]
    fn rejects_aids_outside_scheme_rid_namespace() {
        let profile = std::str::from_utf8(VALID_PROFILE)
            .unwrap()
            .replace(r#""aid": "A0000000031010""#, r#""aid": "A0000000041010""#);

        assert_eq!(
            load_profile_set(profile.as_bytes(), &policy(SignatureStatus::Verified)).unwrap_err(),
            KernelError::InvalidProfile
        );
    }

    #[test]
    fn rejects_duplicate_scheme_rids() {
        let profile = std::str::from_utf8(VALID_PROFILE).unwrap();
        let duplicate_scheme = duplicate_first_array_object(profile, "scheme_profiles");

        assert_eq!(
            load_profile_set(
                duplicate_scheme.as_bytes(),
                &policy(SignatureStatus::Verified)
            )
            .unwrap_err(),
            KernelError::InvalidProfile
        );
    }

    #[test]
    fn rejects_certification_capk_checksum_mismatch_or_metadata_drift() {
        let profile = std::str::from_utf8(VALID_PROFILE).unwrap();
        let bad_checksum = profile.replace(
            "\"checksum_hex\": \"E7BE39F210609E8609E23255BC1B54E81C7EC5D5\"",
            "\"checksum_hex\": \"E7BE39F210609E8609E23255BC1B54E81C7EC5D4\"",
        );
        assert_eq!(
            load_profile_set(bad_checksum.as_bytes(), &policy(SignatureStatus::Verified))
                .unwrap_err(),
            KernelError::InvalidProfile
        );

        let bad_algorithm = profile.replace(
            "\"checksum_algorithm\": \"sha1(rid || key_index || modulus || exponent)\"",
            "\"checksum_algorithm\": \"sha1(modulus || exponent)\"",
        );
        assert_eq!(
            load_profile_set(bad_algorithm.as_bytes(), &policy(SignatureStatus::Verified))
                .unwrap_err(),
            KernelError::InvalidProfile
        );

        let bad_scope = profile.replace(
            "\"checksum_scope\": [\"rid\", \"key_index\", \"modulus_hex\", \"exponent_hex\"]",
            "\"checksum_scope\": [\"modulus_hex\", \"exponent_hex\"]",
        );
        assert_eq!(
            load_profile_set(bad_scope.as_bytes(), &policy(SignatureStatus::Verified)).unwrap_err(),
            KernelError::InvalidProfile
        );
    }

    #[test]
    fn rejects_invalid_capk_public_key_components() {
        for exponent_hex in ["01", "02", "000003", "01000103"] {
            let profile = profile_with_capk_exponent(exponent_hex);
            assert_eq!(
                load_profile_set(profile.as_bytes(), &policy(SignatureStatus::Verified))
                    .unwrap_err(),
                KernelError::InvalidProfile
            );
        }

        let profile = std::str::from_utf8(VALID_PROFILE).unwrap();
        let leading_zero_modulus =
            profile.replace(r#""modulus_hex": "D2E5F5"#, r#""modulus_hex": "00E5F5"#);
        assert_eq!(
            load_profile_set(
                leading_zero_modulus.as_bytes(),
                &policy(SignatureStatus::Verified)
            )
            .unwrap_err(),
            KernelError::InvalidProfile
        );
    }

    #[test]
    fn rejects_unsigned_certification_profile_rollback_and_replay() {
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

        let replay = ConfigLoadPolicy {
            candidate_version: 2,
            installed_version: 2,
            ..policy(SignatureStatus::Verified)
        };
        assert_eq!(
            load_profile_set(VALID_PROFILE, &replay).unwrap_err(),
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
    fn rejects_cfg_002_profile_schema_and_field_failures() {
        assert_eq!(
            load_profile_set(
                br#"{"scheme_profiles":"#,
                &policy(SignatureStatus::Verified)
            )
            .unwrap_err(),
            KernelError::ParseError
        );

        let profile = std::str::from_utf8(VALID_PROFILE).unwrap();
        let leading_zero_number = profile.replace(r#""priority": 10,"#, r#""priority": 010,"#);
        assert_eq!(
            load_profile_set(
                leading_zero_number.as_bytes(),
                &policy(SignatureStatus::Verified)
            )
            .unwrap_err(),
            KernelError::ParseError
        );

        let unknown_root = profile.replace(
            r#""scheme_profiles": ["#,
            r#""mandatory_future_schema": true,
      "scheme_profiles": ["#,
        );
        assert_eq!(
            load_profile_set(unknown_root.as_bytes(), &policy(SignatureStatus::Verified))
                .unwrap_err(),
            KernelError::InvalidProfile
        );

        let unknown_aid = profile.replace(
            r#""partial_selection": true,"#,
            r#""partial_selection": true,
          "mandatory_terminal_parameter_length": 9,"#,
        );
        assert_eq!(
            load_profile_set(unknown_aid.as_bytes(), &policy(SignatureStatus::Verified))
                .unwrap_err(),
            KernelError::InvalidProfile
        );

        let short_aid = profile.replace(r#""aid": "A0000000031010""#, r#""aid": "A000""#);
        assert_eq!(
            load_profile_set(short_aid.as_bytes(), &policy(SignatureStatus::Verified)).unwrap_err(),
            KernelError::InvalidProfile
        );

        let invalid_hex = profile.replace(
            r#""tac_online": "E0F8C80000""#,
            r#""tac_online": "E0F8C8000Z""#,
        );
        assert_eq!(
            load_profile_set(invalid_hex.as_bytes(), &policy(SignatureStatus::Verified))
                .unwrap_err(),
            KernelError::ParseError
        );

        let invalid_offline_limits = profile.replace(
            r#""random_selection_percent": 5,"#,
            r#""random_selection_percent": 5,
          "lower_consecutive_offline_limit": 5,
          "upper_consecutive_offline_limit": 2,"#,
        );
        assert_eq!(
            load_profile_set(
                invalid_offline_limits.as_bytes(),
                &policy(SignatureStatus::Verified)
            )
            .unwrap_err(),
            KernelError::InvalidProfile
        );

        let duplicate_transaction_type_floor_limit = profile.replace(
            r#""transaction_type_floor_limits": [
            {"transaction_type": "01", "floor_limit": 10000}
          ],"#,
            r#""transaction_type_floor_limits": [
            {"transaction_type": "01", "floor_limit": 10000},
            {"transaction_type": "01", "floor_limit": 20000}
          ],"#,
        );
        assert_eq!(
            load_profile_set(
                duplicate_transaction_type_floor_limit.as_bytes(),
                &policy(SignatureStatus::Verified)
            )
            .unwrap_err(),
            KernelError::InvalidProfile
        );

        let malformed_transaction_type_floor_limit = profile.replace(
            r#""transaction_type": "01""#,
            r#""transaction_type": "0102""#,
        );
        assert_eq!(
            load_profile_set(
                malformed_transaction_type_floor_limit.as_bytes(),
                &policy(SignatureStatus::Verified)
            )
            .unwrap_err(),
            KernelError::InvalidProfile
        );

        let non_hex_key_material =
            profile.replace(r#""modulus_hex": "D2E5F5"#, r#""modulus_hex": "Z2E5F5"#);
        assert_eq!(
            load_profile_set(
                non_hex_key_material.as_bytes(),
                &policy(SignatureStatus::Verified)
            )
            .unwrap_err(),
            KernelError::ParseError
        );
    }

    #[test]
    fn rejects_oversized_transaction_type_floor_limit_profiles() {
        let profile = std::str::from_utf8(VALID_PROFILE).unwrap();
        let entries = (0..=MAX_TRANSACTION_TYPE_FLOOR_LIMITS)
            .map(|index| {
                format!(
                    r#"{{"transaction_type": "{index:02X}", "floor_limit": {}}}"#,
                    10_000 + index
                )
            })
            .collect::<Vec<_>>()
            .join(",\n            ");
        let oversized = profile.replace(
            r#""transaction_type_floor_limits": [
            {"transaction_type": "01", "floor_limit": 10000}
          ],"#,
            &format!(
                r#""transaction_type_floor_limits": [
            {entries}
          ],"#
            ),
        );

        assert_eq!(
            load_profile_set(oversized.as_bytes(), &policy(SignatureStatus::Verified)).unwrap_err(),
            KernelError::InvalidProfile
        );
    }

    #[test]
    fn rejects_inconsistent_contactless_limit_ordering() {
        let profile = std::str::from_utf8(VALID_PROFILE).unwrap().replace(
            r#""contactless_cvm_limit": 3000"#,
            r#""contactless_cvm_limit": 6000"#,
        );

        assert_eq!(
            load_profile_set(profile.as_bytes(), &policy(SignatureStatus::Verified)).unwrap_err(),
            KernelError::InvalidProfile
        );
    }

    #[test]
    fn rejects_profile_json_depth_limit_overflow() {
        let mut json = String::new();
        for _ in 0..=MAX_JSON_DEPTH {
            json.push('[');
        }
        json.push_str("null");
        for _ in 0..=MAX_JSON_DEPTH {
            json.push(']');
        }

        assert_eq!(
            load_profile_set(json.as_bytes(), &policy(SignatureStatus::Verified)).unwrap_err(),
            KernelError::LengthOverflow
        );
    }

    #[test]
    fn rejects_profile_json_node_limit_overflow() {
        let mut json = String::from("[");
        for index in 0..=MAX_JSON_NODES {
            if index != 0 {
                json.push(',');
            }
            json.push_str("null");
        }
        json.push(']');

        assert_eq!(
            load_profile_set(json.as_bytes(), &policy(SignatureStatus::Verified)).unwrap_err(),
            KernelError::LengthOverflow
        );
    }

    #[test]
    fn rejects_invalid_profile_schema_version() {
        let profile = std::str::from_utf8(VALID_PROFILE).unwrap();
        let missing = profile.replace(
            r#"      "schema_version": "1.0",
"#,
            "",
        );
        assert_eq!(
            load_profile_set(missing.as_bytes(), &policy(SignatureStatus::Verified)).unwrap_err(),
            KernelError::InvalidProfile
        );

        let unsupported =
            profile.replace(r#""schema_version": "1.0","#, r#""schema_version": "2.0","#);
        assert_eq!(
            load_profile_set(unsupported.as_bytes(), &policy(SignatureStatus::Verified))
                .unwrap_err(),
            KernelError::InvalidProfile
        );

        let malformed = profile.replace(r#""schema_version": "1.0","#, r#""schema_version": 1,"#);
        assert_eq!(
            load_profile_set(malformed.as_bytes(), &policy(SignatureStatus::Verified)).unwrap_err(),
            KernelError::ParseError
        );
    }

    #[test]
    fn rejects_blank_certification_profile_source_metadata() {
        let profile = std::str::from_utf8(VALID_PROFILE).unwrap();
        let blank_owner = profile.replace(r#""owner": "scheme_or_acquirer""#, r#""owner": "   ""#);
        assert_eq!(
            load_profile_set(blank_owner.as_bytes(), &policy(SignatureStatus::Verified))
                .unwrap_err(),
            KernelError::InvalidProfile
        );

        let padded_profile_document = profile.replace(
            r#""document": "signed_certification_profile_bundle""#,
            r#""document": " signed_certification_profile_bundle""#,
        );
        assert_eq!(
            load_profile_set(
                padded_profile_document.as_bytes(),
                &policy(SignatureStatus::Verified)
            )
            .unwrap_err(),
            KernelError::InvalidProfile
        );

        let padded_source_version = profile.replace(r#""version": "2""#, r#""version": "2 ""#);
        assert_eq!(
            load_profile_set(
                padded_source_version.as_bytes(),
                &policy(SignatureStatus::Verified)
            )
            .unwrap_err(),
            KernelError::InvalidProfile
        );

        let blank_capk_document = profile.replace(
            r#""document": "signed_certification_capk_bundle""#,
            r#""document": """#,
        );
        assert_eq!(
            load_profile_set(
                blank_capk_document.as_bytes(),
                &policy(SignatureStatus::Verified)
            )
            .unwrap_err(),
            KernelError::InvalidProfile
        );
    }

    #[test]
    fn preserves_and_validates_profile_source_retrieval_dates() {
        let profiles = load_profile_set(VALID_PROFILE, &policy(SignatureStatus::Verified)).unwrap();
        assert_eq!(
            profiles.profile_source.retrieved,
            Some(EmvDate {
                year: 26,
                month: 5,
                day: 21
            })
        );
        assert_eq!(
            profiles.schemes[0].capks[0].source.retrieved,
            Some(EmvDate {
                year: 26,
                month: 5,
                day: 21
            })
        );

        let profile = std::str::from_utf8(VALID_PROFILE).unwrap();
        let bad_retrieved = profile.replace(r#""retrieved": "2026-05-21""#, r#""retrieved": """#);
        assert_eq!(
            load_profile_set(bad_retrieved.as_bytes(), &policy(SignatureStatus::Verified))
                .unwrap_err(),
            KernelError::InvalidProfile
        );

        let missing_profile_retrieved = profile.replacen(
            r#"
        "retrieved": "2026-05-21","#,
            "",
            1,
        );
        assert_eq!(
            load_profile_set(
                missing_profile_retrieved.as_bytes(),
                &policy(SignatureStatus::Verified)
            )
            .unwrap_err(),
            KernelError::InvalidProfile
        );

        let missing_capk_retrieved = profile.replace(
            r#"
            "retrieved": "2026-05-21","#,
            "",
        );
        assert_eq!(
            load_profile_set(
                missing_capk_retrieved.as_bytes(),
                &policy(SignatureStatus::Verified)
            )
            .unwrap_err(),
            KernelError::InvalidProfile
        );

        let malformed_retrieved = profile.replace(
            r#""retrieved": "2026-05-21""#,
            r#""retrieved": "2026-13-21""#,
        );
        assert_eq!(
            load_profile_set(
                malformed_retrieved.as_bytes(),
                &policy(SignatureStatus::Verified)
            )
            .unwrap_err(),
            KernelError::ParseError
        );

        let future_profile_retrieved = profile.replacen(
            r#""retrieved": "2026-05-21""#,
            r#""retrieved": "2026-05-22""#,
            1,
        );
        assert_eq!(
            load_profile_set(
                future_profile_retrieved.as_bytes(),
                &policy(SignatureStatus::Verified)
            )
            .unwrap_err(),
            KernelError::InvalidProfile
        );

        let future_capk_retrieved = profile.replace(
            r#""document": "signed_certification_capk_bundle",
            "version": "2",
            "retrieved": "2026-05-21""#,
            r#""document": "signed_certification_capk_bundle",
            "version": "2",
            "retrieved": "2026-05-22""#,
        );
        assert_eq!(
            load_profile_set(
                future_capk_retrieved.as_bytes(),
                &policy(SignatureStatus::Verified)
            )
            .unwrap_err(),
            KernelError::InvalidProfile
        );
    }

    #[test]
    fn rejects_example_profile_in_certification_or_production_mode() {
        let example = br#"{
          "profile_class": "EXAMPLE_ONLY",
          "profile_source": {
            "owner": "engineering",
            "document": "example_profile",
            "version": "1",
            "verification": "test_only"
          },
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
              "checksum_hex": "E7BE39F210609E8609E23255BC1B54E81C7EC5D5",
              "source": {
                "owner": "scheme_or_acquirer",
                "document": "signed_certification_capk_bundle",
                "version": "2",
                "verification": "external_signature_required"
              }
            }]
          }]
        }"#;

        assert_eq!(
            load_profile_set(example, &policy(SignatureStatus::Verified)).unwrap_err(),
            KernelError::InvalidProfile
        );
        let production = ConfigLoadPolicy {
            mode: BuildMode::Production,
            ..policy(SignatureStatus::Verified)
        };
        assert_eq!(
            load_profile_set(example, &production).unwrap_err(),
            KernelError::InvalidProfile
        );
        let test = ConfigLoadPolicy {
            mode: BuildMode::Test,
            signature_status: SignatureStatus::NotPresent,
            ..policy(SignatureStatus::Verified)
        };
        let profiles = load_profile_set(example, &test).unwrap();
        assert_eq!(profiles.profile_class, ProfileClass::ExampleOnly);
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
    fn rejects_invalid_capk_expiry_calendar_dates() {
        let profile = std::str::from_utf8(VALID_PROFILE).unwrap();
        for expiry in ["2030-02-30", "2030-04-31", "2030-00-15", "2030-13-01"] {
            let invalid_date = profile.replace(
                r#""expiry": "2030-12-31""#,
                &format!(r#""expiry": "{expiry}""#),
            );
            assert_eq!(
                load_profile_set(invalid_date.as_bytes(), &policy(SignatureStatus::Verified))
                    .unwrap_err(),
                KernelError::ParseError,
                "expected invalid expiry {expiry} to be rejected"
            );
        }
    }

    #[test]
    fn rejects_contact_kernel_type_that_reuses_c8() {
        let profile = std::str::from_utf8(VALID_PROFILE).unwrap().replace(
            r#""contact_kernel_type": "legacy_visa""#,
            r#""contact_kernel_type": "c8_contactless""#,
        );
        assert_eq!(
            load_profile_set(profile.as_bytes(), &policy(SignatureStatus::Verified)).unwrap_err(),
            KernelError::InvalidProfile
        );
    }

    #[test]
    fn rejects_invalid_interface_kernel_mapping_and_duplicate_interfaces() {
        let profile = std::str::from_utf8(VALID_PROFILE).unwrap();

        let missing_contact_kernel = profile.replace(
            r#"        "contact_kernel_type": "legacy_visa",
"#,
            "",
        );
        assert_eq!(
            load_profile_set(
                missing_contact_kernel.as_bytes(),
                &policy(SignatureStatus::Verified)
            )
            .unwrap_err(),
            KernelError::InvalidProfile
        );

        let blank_scheme_name =
            profile.replace(r#""scheme_name": "Visa""#, r#""scheme_name": "   ""#);
        assert_eq!(
            load_profile_set(
                blank_scheme_name.as_bytes(),
                &policy(SignatureStatus::Verified)
            )
            .unwrap_err(),
            KernelError::InvalidProfile
        );

        let blank_kernel_type = profile.replace(
            r#""kernel_type": "c8_contactless""#,
            r#""kernel_type": "   ""#,
        );
        assert_eq!(
            load_profile_set(
                blank_kernel_type.as_bytes(),
                &policy(SignatureStatus::Verified)
            )
            .unwrap_err(),
            KernelError::InvalidProfile
        );

        let blank_contact_kernel_type = profile.replace(
            r#""contact_kernel_type": "legacy_visa""#,
            r#""contact_kernel_type": "   ""#,
        );
        assert_eq!(
            load_profile_set(
                blank_contact_kernel_type.as_bytes(),
                &policy(SignatureStatus::Verified)
            )
            .unwrap_err(),
            KernelError::InvalidProfile
        );

        let non_c8_contactless = profile.replace(
            r#""kernel_type": "c8_contactless""#,
            r#""kernel_type": "legacy_contactless""#,
        );
        assert_eq!(
            load_profile_set(
                non_c8_contactless.as_bytes(),
                &policy(SignatureStatus::Verified)
            )
            .unwrap_err(),
            KernelError::InvalidProfile
        );

        let duplicate_interfaces = profile.replace(
            r#""interfaces": ["contact", "contactless"]"#,
            r#""interfaces": ["contact", "contact", "contactless"]"#,
        );
        assert_eq!(
            load_profile_set(
                duplicate_interfaces.as_bytes(),
                &policy(SignatureStatus::Verified)
            )
            .unwrap_err(),
            KernelError::InvalidProfile
        );
    }

    #[test]
    fn rejects_malformed_default_cdol1() {
        let profile = std::str::from_utf8(VALID_PROFILE).unwrap().replace(
            r#""default_cdol1": "9F370495059F02069A039C019F1A029F3403""#,
            r#""default_cdol1": "9F""#,
        );
        assert_eq!(
            load_profile_set(profile.as_bytes(), &policy(SignatureStatus::Verified)).unwrap_err(),
            KernelError::ParseError
        );
    }

    #[test]
    fn rejects_invalid_or_duplicate_critical_script_ins_policy() {
        let invalid = br#"{
          "profile_class": "CERTIFICATION",
          "profile_source": {
            "owner": "scheme_or_acquirer",
            "document": "signed_certification_profile_bundle",
            "version": "2",
            "verification": "external_signature_required"
          },
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
              "checksum_hex": "E7BE39F210609E8609E23255BC1B54E81C7EC5D5",
              "source": {
                "owner": "scheme_or_acquirer",
                "document": "signed_certification_capk_bundle",
                "version": "2",
                "verification": "external_signature_required"
              }
            }]
          }]
        }"#;
        assert_eq!(
            load_profile_set(invalid, &policy(SignatureStatus::Verified)).unwrap_err(),
            KernelError::InvalidProfile
        );

        let duplicate = std::str::from_utf8(VALID_PROFILE).unwrap().replace(
            r#""critical_issuer_script_ins": ["E2"]"#,
            r#""critical_issuer_script_ins": ["E2", "E2"]"#,
        );
        assert_eq!(
            load_profile_set(duplicate.as_bytes(), &policy(SignatureStatus::Verified)).unwrap_err(),
            KernelError::InvalidProfile
        );
    }

    #[test]
    fn cda_request_encoding_is_profile_defined_and_non_colliding() {
        assert_eq!(
            parse_cda_request_encoding("CDOL1_bit").unwrap(),
            CdaRequestEncoding::InCdolData
        );
        assert_eq!(
            parse_cda_request_encoding("P1_low_bits_0x10").unwrap(),
            CdaRequestEncoding::P1LowBits(0x10)
        );
        assert_eq!(
            parse_cda_request_encoding("P1_low_bits_0x40").unwrap_err(),
            KernelError::InvalidProfile
        );
        assert_eq!(
            parse_cda_request_encoding("implicit").unwrap_err(),
            KernelError::InvalidProfile
        );
    }

    #[test]
    fn rejects_inconsistent_cda_profile_controls() {
        let profile = std::str::from_utf8(VALID_PROFILE).unwrap();

        let missing_encoding = profile.replace(
            r#"
          "cda_request_encoding": "CDOL1_bit","#,
            "",
        );
        assert_eq!(
            load_profile_set(
                missing_encoding.as_bytes(),
                &policy(SignatureStatus::Verified)
            )
            .unwrap_err(),
            KernelError::InvalidProfile
        );

        let unsupported_with_encoding =
            profile.replace(r#""cda_supported": true,"#, r#""cda_supported": false,"#);
        assert_eq!(
            load_profile_set(
                unsupported_with_encoding.as_bytes(),
                &policy(SignatureStatus::Verified)
            )
            .unwrap_err(),
            KernelError::InvalidProfile
        );
    }
}
