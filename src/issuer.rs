use crate::error::{KernelError, KernelResult};
use crate::state::{Tsi, Tvr};
use crate::tlv;

pub const MAX_SCRIPT_COMMANDS: usize = 32;
pub const MAX_SCRIPT_COMMAND_LEN: usize = 261;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScriptPhase {
    BeforeFinalGenerateAc,
    AfterFinalGenerateAc,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuerScript {
    pub phase: ScriptPhase,
    pub identifier: Option<Vec<u8>>,
    pub commands: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostResponse {
    pub authorization_response_code: Option<[u8; 2]>,
    pub issuer_authentication_data: Option<Vec<u8>>,
    pub scripts: Vec<IssuerScript>,
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
    let authorization_response_code = match tlv::find_first(&tlvs, &[0x8a]) {
        Some(value) if value.len() == 2 => Some([value[0], value[1]]),
        Some(_) => return Err(KernelError::ParseError),
        None => None,
    };
    let issuer_authentication_data = tlv::find_first(&tlvs, &[0x91]).map(|value| value.to_vec());
    let mut scripts = Vec::new();
    collect_scripts(&tlvs, &mut scripts)?;

    Ok(HostResponse {
        authorization_response_code,
        issuer_authentication_data,
        scripts,
    })
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
    for item in tlvs {
        let phase = match item.tag {
            [0x71] => Some(ScriptPhase::BeforeFinalGenerateAc),
            [0x72] => Some(ScriptPhase::AfterFinalGenerateAc),
            _ => None,
        };
        if let Some(phase) = phase {
            scripts.push(parse_script_template(item, phase)?);
        }
        collect_scripts(&item.children, scripts)?;
    }
    Ok(())
}

fn parse_script_template(
    template: &tlv::Tlv<'_>,
    phase: ScriptPhase,
) -> KernelResult<IssuerScript> {
    let identifier = tlv::find_first(&template.children, &[0x9f, 0x18]).map(|value| value.to_vec());
    let mut commands = Vec::new();
    collect_script_commands(&template.children, &mut commands)?;
    if commands.is_empty() {
        return Err(KernelError::ParseError);
    }
    Ok(IssuerScript {
        phase,
        identifier,
        commands,
    })
}

fn collect_script_commands(tlvs: &[tlv::Tlv<'_>], commands: &mut Vec<Vec<u8>>) -> KernelResult<()> {
    for item in tlvs {
        if item.tag == [0x86] {
            if item.value.is_empty() || item.value.len() > MAX_SCRIPT_COMMAND_LEN {
                return Err(KernelError::ParseError);
            }
            if commands.len() >= MAX_SCRIPT_COMMANDS {
                return Err(KernelError::LengthOverflow);
            }
            commands.push(item.value.to_vec());
        }
        collect_script_commands(&item.children, commands)?;
    }
    Ok(())
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

        assert_eq!(response.authorization_response_code, Some([b'0', b'0']));
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
}
