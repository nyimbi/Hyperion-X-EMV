use crate::error::{KernelError, KernelResult};
use crate::state::{Tsi, Tvr};
use crate::tlv;
use core::fmt;

pub const MAX_SCRIPT_COMMANDS: usize = 32;
pub const MAX_SCRIPT_COMMAND_LEN: usize = 261;
const ISSUER_SCRIPT_IDENTIFIER_LEN: usize = 4;
const ISSUER_AUTHENTICATION_DATA_MIN_LEN: usize = 8;
const ISSUER_AUTHENTICATION_DATA_MAX_LEN: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScriptPhase {
    BeforeFinalGenerateAc,
    AfterFinalGenerateAc,
}

#[derive(Clone, Eq, PartialEq)]
pub struct IssuerScript {
    pub phase: ScriptPhase,
    pub identifier: Option<Vec<u8>>,
    pub commands: Vec<Vec<u8>>,
}

impl fmt::Debug for IssuerScript {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let command_lengths: Vec<usize> = self.commands.iter().map(Vec::len).collect();
        f.debug_struct("IssuerScript")
            .field("phase", &self.phase)
            .field("identifier_len", &self.identifier.as_ref().map(Vec::len))
            .field("command_count", &self.commands.len())
            .field("command_lengths", &command_lengths)
            .field(
                "data_policy",
                &"issuer script identifiers and APDU command bytes redacted for crash safety",
            )
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct HostResponse {
    pub authorization_response_code: [u8; 2],
    pub issuer_authentication_data: Option<Vec<u8>>,
    pub scripts: Vec<IssuerScript>,
}

impl fmt::Debug for HostResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HostResponse")
            .field(
                "authorization_response_code",
                &self.authorization_response_code,
            )
            .field(
                "issuer_authentication_data_len",
                &self.issuer_authentication_data.as_ref().map(Vec::len),
            )
            .field("script_count", &self.scripts.len())
            .field("scripts", &self.scripts)
            .field(
                "data_policy",
                &"issuer authentication data and script bytes redacted for crash safety",
            )
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScriptCommandResult {
    pub sw1: u8,
    pub sw2: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScriptExecutionSummary {
    pub tvr: Tvr,
    pub tsi: Tsi,
    pub results: Vec<ScriptCommandResult>,
}

pub fn parse_host_response(input: &[u8]) -> KernelResult<HostResponse> {
    let tlvs = tlv::parse_many(input)?;
    reject_nested_host_response_objects(&tlvs)?;

    let authorization_response_code = match tlv::find_unique_direct(&tlvs, &[0x8a])? {
        Some(value) => Some(parse_authorization_response_code(value)?),
        None => None,
    };
    let issuer_authentication_data = match tlv::find_unique_direct(&tlvs, &[0x91])? {
        Some(value)
            if (ISSUER_AUTHENTICATION_DATA_MIN_LEN..=ISSUER_AUTHENTICATION_DATA_MAX_LEN)
                .contains(&value.len()) =>
        {
            Some(value.to_vec())
        }
        Some(_) => return Err(KernelError::ParseError),
        None => None,
    };
    let mut scripts = Vec::new();
    collect_scripts(&tlvs, &mut scripts)?;
    let authorization_response_code =
        authorization_response_code.ok_or(KernelError::MissingMandatoryTag)?;

    Ok(HostResponse {
        authorization_response_code,
        issuer_authentication_data,
        scripts,
    })
}

fn parse_authorization_response_code(value: &[u8]) -> KernelResult<[u8; 2]> {
    if value.len() != 2 {
        return Err(KernelError::ParseError);
    }
    if !value
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || *byte == b' ')
    {
        return Err(KernelError::ParseError);
    }
    Ok([value[0], value[1]])
}

pub fn apply_script_results(
    phase: ScriptPhase,
    results: &[ScriptCommandResult],
    mut tvr: Tvr,
    mut tsi: Tsi,
) -> ScriptExecutionSummary {
    if !results.is_empty() {
        tsi.set(Tsi::SCRIPT_PROCESSING_PERFORMED);
    }
    if results
        .iter()
        .any(|result| result.sw1 != 0x90 || result.sw2 != 0x00)
    {
        match phase {
            ScriptPhase::BeforeFinalGenerateAc => {
                tvr.set(Tvr::B5_SCRIPT_PROCESSING_FAILED_BEFORE_FINAL_GAC);
            }
            ScriptPhase::AfterFinalGenerateAc => {
                tvr.set(Tvr::B5_SCRIPT_PROCESSING_FAILED_AFTER_FINAL_GAC);
            }
        }
    }
    ScriptExecutionSummary {
        tvr,
        tsi,
        results: results.to_vec(),
    }
}

fn collect_scripts(tlvs: &[tlv::Tlv<'_>], scripts: &mut Vec<IssuerScript>) -> KernelResult<()> {
    let mut total_commands = 0usize;
    for item in tlvs {
        let phase = match item.tag {
            [0x71] => Some(ScriptPhase::BeforeFinalGenerateAc),
            [0x72] => Some(ScriptPhase::AfterFinalGenerateAc),
            _ => None,
        };
        let Some(phase) = phase else {
            continue;
        };
        let script = parse_script_template(item, phase)?;
        total_commands = total_commands
            .checked_add(script.commands.len())
            .ok_or(KernelError::LengthOverflow)?;
        if total_commands > MAX_SCRIPT_COMMANDS {
            return Err(KernelError::LengthOverflow);
        }
        scripts.push(script);
    }
    Ok(())
}

fn reject_nested_host_response_objects(tlvs: &[tlv::Tlv<'_>]) -> KernelResult<()> {
    for item in tlvs {
        reject_nested_response_objects(&item.children)?;
    }
    Ok(())
}

fn reject_nested_response_objects(tlvs: &[tlv::Tlv<'_>]) -> KernelResult<()> {
    for item in tlvs {
        if matches!(item.tag, [0x8a] | [0x91] | [0x71] | [0x72]) {
            return Err(KernelError::ParseError);
        }
        reject_nested_response_objects(&item.children)?;
    }
    Ok(())
}

fn parse_script_template(
    template: &tlv::Tlv<'_>,
    phase: ScriptPhase,
) -> KernelResult<IssuerScript> {
    let mut identifier = None;
    let mut commands = Vec::new();

    for item in &template.children {
        match item.tag {
            [0x9f, 0x18] => {
                if identifier.is_some() || item.value.len() != ISSUER_SCRIPT_IDENTIFIER_LEN {
                    return Err(KernelError::ParseError);
                }
                identifier = Some(item.value.to_vec());
            }
            [0x86] => {
                if item.value.is_empty() {
                    return Err(KernelError::ParseError);
                }
                if item.value.len() > MAX_SCRIPT_COMMAND_LEN {
                    return Err(KernelError::LengthOverflow);
                }
                validate_script_command_apdu(item.value)?;
                if commands.len() >= MAX_SCRIPT_COMMANDS {
                    return Err(KernelError::LengthOverflow);
                }
                commands.push(item.value.to_vec());
            }
            _ => {
                return Err(KernelError::ParseError);
            }
        }
    }

    if commands.is_empty() {
        return Err(KernelError::ParseError);
    }
    Ok(IssuerScript {
        phase,
        identifier,
        commands,
    })
}

fn validate_script_command_apdu(command: &[u8]) -> KernelResult<()> {
    if command.len() < 4 {
        return Err(KernelError::ParseError);
    }
    if command.len() <= 5 {
        return Ok(());
    }

    let lc = command[4] as usize;
    if lc == 0 {
        return Err(KernelError::ParseError);
    }
    let data_end = 5usize.checked_add(lc).ok_or(KernelError::LengthOverflow)?;
    if command.len() == data_end || command.len() == data_end + 1 {
        Ok(())
    } else {
        Err(KernelError::ParseError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{Tsi, Tvr};

    #[test]
    fn parses_arpc_arc_and_issuer_scripts() {
        let response = parse_host_response(&[
            0x8a, 0x02, b'0', b'0', 0x91, 0x08, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x71, 0x0f, 0x9f, 0x18, 0x04, 0xde, 0xad, 0xbe, 0xef, 0x86, 0x06, 0x00, 0xda, 0x00,
            0x00, 0x01, 0xaa, 0x72, 0x08, 0x86, 0x06, 0x80, 0xe2, 0x00, 0x00, 0x01, 0xbb,
        ])
        .unwrap();

        assert_eq!(response.authorization_response_code, [b'0', b'0']);
        assert_eq!(
            response.issuer_authentication_data,
            Some(vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88])
        );
        assert_eq!(response.scripts.len(), 2);
        assert_eq!(
            response.scripts[0].phase,
            ScriptPhase::BeforeFinalGenerateAc
        );
        assert_eq!(
            response.scripts[0].identifier,
            Some(vec![0xde, 0xad, 0xbe, 0xef])
        );
        assert_eq!(response.scripts[1].phase, ScriptPhase::AfterFinalGenerateAc);
    }

    #[test]
    fn script_results_set_phase_specific_tvr_bits_and_tsi() {
        let before = apply_script_results(
            ScriptPhase::BeforeFinalGenerateAc,
            &[ScriptCommandResult {
                sw1: 0x6a,
                sw2: 0x80,
            }],
            Tvr::cleared(),
            Tsi::cleared(),
        );
        assert!(before
            .tvr
            .is_set(Tvr::B5_SCRIPT_PROCESSING_FAILED_BEFORE_FINAL_GAC));
        assert!(before.tsi.is_set(Tsi::SCRIPT_PROCESSING_PERFORMED));

        let after = apply_script_results(
            ScriptPhase::AfterFinalGenerateAc,
            &[ScriptCommandResult {
                sw1: 0x69,
                sw2: 0x85,
            }],
            Tvr::cleared(),
            Tsi::cleared(),
        );
        assert!(after
            .tvr
            .is_set(Tvr::B5_SCRIPT_PROCESSING_FAILED_AFTER_FINAL_GAC));
    }

    #[test]
    fn rejects_script_templates_without_commands() {
        assert_eq!(
            parse_host_response(&[0x71, 0x06, 0x9f, 0x18, 0x03, 0x01, 0x02, 0x03]).unwrap_err(),
            KernelError::ParseError
        );
    }

    #[test]
    fn rejects_malformed_issuer_script_identifier_lengths() {
        assert_eq!(
            parse_host_response(&[
                0x71, 0x0c, 0x9f, 0x18, 0x01, 0xde, 0x86, 0x06, 0x00, 0xda, 0x00, 0x00, 0x01, 0xaa,
            ])
            .unwrap_err(),
            KernelError::ParseError
        );
        assert_eq!(
            parse_host_response(&[
                0x71, 0x10, 0x9f, 0x18, 0x05, 0xde, 0xad, 0xbe, 0xef, 0x01, 0x86, 0x06, 0x00, 0xda,
                0x00, 0x00, 0x01, 0xaa,
            ])
            .unwrap_err(),
            KernelError::ParseError
        );
    }

    #[test]
    fn rejects_malformed_issuer_script_command_apdus() {
        assert_eq!(
            parse_host_response(&[0x71, 0x04, 0x86, 0x02, 0x00, 0xda]).unwrap_err(),
            KernelError::ParseError
        );
        assert_eq!(
            parse_host_response(&[0x71, 0x08, 0x86, 0x06, 0x00, 0xda, 0x00, 0x00, 0x02, 0xaa])
                .unwrap_err(),
            KernelError::ParseError
        );
        assert_eq!(
            parse_host_response(&[0x71, 0x08, 0x86, 0x06, 0x00, 0xda, 0x00, 0x00, 0x00, 0xaa])
                .unwrap_err(),
            KernelError::ParseError
        );
    }

    #[test]
    fn rejects_issuer_script_commands_above_length_limit() {
        let command = vec![0x00; MAX_SCRIPT_COMMAND_LEN + 1];
        let template_len = 1 + 3 + command.len();
        let mut host = vec![
            0x71,
            0x82,
            (template_len >> 8) as u8,
            template_len as u8,
            0x86,
            0x82,
            (command.len() >> 8) as u8,
            command.len() as u8,
        ];
        host.extend_from_slice(&command);

        assert_eq!(
            parse_host_response(&host).unwrap_err(),
            KernelError::LengthOverflow
        );
    }

    #[test]
    fn rejects_nested_or_duplicate_issuer_script_objects() {
        assert_eq!(
            parse_host_response(&[
                0x71, 0x0a, 0xa5, 0x08, 0x86, 0x06, 0x00, 0xda, 0x00, 0x00, 0x01, 0xaa,
            ])
            .unwrap_err(),
            KernelError::ParseError
        );
        assert_eq!(
            parse_host_response(&[
                0x71, 0x12, 0x9f, 0x18, 0x02, 0x01, 0x02, 0x9f, 0x18, 0x02, 0x03, 0x04, 0x86, 0x06,
                0x00, 0xda, 0x00, 0x00, 0x01, 0xaa,
            ])
            .unwrap_err(),
            KernelError::ParseError
        );

        assert_eq!(
            parse_host_response(&[
                0x70, 0x0a, 0x71, 0x08, 0x86, 0x06, 0x00, 0xda, 0x00, 0x00, 0x01, 0xaa,
            ])
            .unwrap_err(),
            KernelError::ParseError
        );
        assert_eq!(
            parse_host_response(&[
                0x70, 0x0a, 0x72, 0x08, 0x86, 0x06, 0x80, 0xe2, 0x00, 0x00, 0x01, 0xbb,
            ])
            .unwrap_err(),
            KernelError::ParseError
        );
    }

    #[test]
    fn rejects_malformed_issuer_authentication_data() {
        assert_eq!(
            parse_host_response(&[0x8a, 0x02, b'0', b'0', 0x91, 0x07, 1, 2, 3, 4, 5, 6, 7])
                .unwrap_err(),
            KernelError::ParseError
        );
        let too_long = [
            0x8a, 0x02, b'0', b'0', 0x91, 0x11, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            16, 17,
        ];
        assert_eq!(
            parse_host_response(&too_long).unwrap_err(),
            KernelError::ParseError
        );
    }

    #[test]
    fn rejects_non_alphanumeric_authorization_response_codes() {
        assert_eq!(
            parse_host_response(&[0x8a, 0x02, 0x00, b'0']).unwrap_err(),
            KernelError::ParseError
        );
        assert_eq!(
            parse_host_response(&[0x8a, 0x02, b'0', 0xff]).unwrap_err(),
            KernelError::ParseError
        );
        assert_eq!(
            parse_host_response(&[0x8a, 0x02, b' ', b'0'])
                .unwrap()
                .authorization_response_code,
            [b' ', b'0']
        );
    }

    #[test]
    fn rejects_host_response_without_authorization_response_code() {
        assert_eq!(
            parse_host_response(&[0x91, 0x08, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88])
                .unwrap_err(),
            KernelError::MissingMandatoryTag
        );
        assert_eq!(
            parse_host_response(&[0x71, 0x08, 0x86, 0x06, 0x00, 0xda, 0x00, 0x00, 0x01, 0xaa])
                .unwrap_err(),
            KernelError::MissingMandatoryTag
        );
    }

    #[test]
    fn rejects_nested_or_duplicate_host_response_auth_objects() {
        assert_eq!(
            parse_host_response(&[0x70, 0x04, 0x8a, 0x02, b'0', b'0']).unwrap_err(),
            KernelError::ParseError
        );
        assert_eq!(
            parse_host_response(&[
                0x70, 0x0a, 0x91, 0x08, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            ])
            .unwrap_err(),
            KernelError::ParseError
        );
        assert_eq!(
            parse_host_response(&[0x8a, 0x02, b'0', b'0', 0x8a, 0x02, b'0', b'5']).unwrap_err(),
            KernelError::ParseError
        );
        assert_eq!(
            parse_host_response(&[
                0x91, 0x08, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x91, 0x08, 0x21, 0x22,
                0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
            ])
            .unwrap_err(),
            KernelError::ParseError
        );
    }

    #[test]
    fn rejects_cumulative_issuer_script_command_overflow() {
        fn push_script_template(host: &mut Vec<u8>, command_count: u8) {
            let value_len = command_count as usize * 6;
            host.push(0x71);
            host.push(value_len as u8);
            for sequence in 0..command_count {
                host.extend_from_slice(&[0x86, 0x04, 0x00, 0xda, 0x00, sequence]);
            }
        }

        let mut host = Vec::new();
        push_script_template(&mut host, 16);
        push_script_template(&mut host, 17);

        assert_eq!(
            parse_host_response(&host).unwrap_err(),
            KernelError::LengthOverflow
        );
    }

    #[test]
    fn host_response_debug_redacts_issuer_authentication_and_scripts() {
        let response = parse_host_response(&[
            0x8a, 0x02, b'0', b'0', 0x91, 0x08, 0xde, 0xad, 0xbe, 0xef, 0xaa, 0xbb, 0xcc, 0xdd,
            0x71, 0x0f, 0x9f, 0x18, 0x04, 0x01, 0x02, 0x03, 0x04, 0x86, 0x06, 0x00, 0xda, 0x00,
            0x00, 0x01, 0xaa,
        ])
        .unwrap();

        let debug = format!("{response:?}");
        assert!(debug.contains("HostResponse"));
        assert!(debug.contains("redacted for crash safety"));
        assert!(debug.contains("issuer_authentication_data_len"));
        assert!(debug.contains("command_lengths"));
        for raw_byte in ["222", "173", "190", "239", "218", "170"] {
            assert!(!debug.contains(raw_byte));
        }
    }
}
