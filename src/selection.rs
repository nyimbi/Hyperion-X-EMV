use crate::apdu::Interface;
use crate::config::ProfileSet;
use crate::error::{KernelError, KernelResult};
use crate::tlv;

pub const MAX_CANDIDATE_AIDS: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectionCandidate {
    pub aid: Vec<u8>,
    pub scheme_index: usize,
    pub aid_index: usize,
    pub priority: u8,
    pub partial_selection: bool,
}

pub fn parse_fci_candidate_aids(fci: &[u8]) -> KernelResult<Vec<Vec<u8>>> {
    let parsed = tlv::parse_many(fci)?;
    if parsed.len() != 1 || parsed[0].tag != [0x6f] || !parsed[0].constructed {
        return Err(KernelError::MissingMandatoryTag);
    }

    let mut candidates = Vec::new();
    for fci_child in &parsed[0].children {
        if fci_child.tag != [0xa5] || !fci_child.constructed {
            continue;
        }
        for proprietary_child in &fci_child.children {
            if proprietary_child.tag != [0xbf, 0x0c] || !proprietary_child.constructed {
                continue;
            }
            for directory_entry in &proprietary_child.children {
                if directory_entry.tag != [0x61] || !directory_entry.constructed {
                    continue;
                }
                let aid = tlv::find_unique_direct(&directory_entry.children, &[0x4f])?
                    .ok_or(KernelError::MissingMandatoryTag)?;
                push_unique_aid(&mut candidates, aid)?;
            }
        }
    }
    Ok(candidates)
}

pub fn direct_profile_candidates(
    profiles: &ProfileSet,
    interface: Interface,
) -> KernelResult<Vec<SelectionCandidate>> {
    let mut out = Vec::new();
    for (scheme_index, scheme) in profiles.schemes.iter().enumerate() {
        for (aid_index, aid) in scheme.aids.iter().enumerate() {
            if aid
                .interfaces
                .iter()
                .any(|item| item == interface_name(interface))
            {
                out.push(SelectionCandidate {
                    aid: aid.aid.clone(),
                    scheme_index,
                    aid_index,
                    priority: aid.priority,
                    partial_selection: aid.partial_selection,
                });
            }
        }
    }
    sort_candidates(&mut out);
    if out.is_empty() {
        return Err(KernelError::NoCommonAid);
    }
    Ok(out)
}

pub fn match_profile_candidates(
    profiles: &ProfileSet,
    interface: Interface,
    card_candidates: &[Vec<u8>],
) -> KernelResult<Vec<SelectionCandidate>> {
    if card_candidates.len() > MAX_CANDIDATE_AIDS {
        return Err(KernelError::LengthOverflow);
    }

    let mut out = Vec::new();
    for (scheme_index, scheme) in profiles.schemes.iter().enumerate() {
        for (aid_index, aid) in scheme.aids.iter().enumerate() {
            if !aid
                .interfaces
                .iter()
                .any(|item| item == interface_name(interface))
            {
                continue;
            }
            if card_candidates
                .iter()
                .any(|card| aid_matches(card, &aid.aid, aid.partial_selection))
            {
                out.push(SelectionCandidate {
                    aid: aid.aid.clone(),
                    scheme_index,
                    aid_index,
                    priority: aid.priority,
                    partial_selection: aid.partial_selection,
                });
            }
        }
    }
    sort_candidates(&mut out);
    if out.is_empty() {
        return Err(KernelError::NoCommonAid);
    }
    Ok(out)
}

fn push_unique_aid(out: &mut Vec<Vec<u8>>, aid: &[u8]) -> KernelResult<()> {
    if !(5..=16).contains(&aid.len()) {
        return Err(KernelError::InvalidProfile);
    }
    if out.len() >= MAX_CANDIDATE_AIDS {
        return Err(KernelError::LengthOverflow);
    }
    if !out.iter().any(|stored| stored == aid) {
        out.push(aid.to_vec());
    }
    Ok(())
}

fn aid_matches(card: &[u8], terminal: &[u8], partial_selection: bool) -> bool {
    card == terminal || (partial_selection && card.starts_with(terminal))
}

fn interface_name(interface: Interface) -> &'static str {
    match interface {
        Interface::Contact => "contact",
        Interface::Contactless => "contactless",
    }
}

fn sort_candidates(candidates: &mut [SelectionCandidate]) {
    candidates.sort_by(|left, right| {
        left.priority
            .cmp(&right.priority)
            .then_with(|| left.aid.cmp(&right.aid))
            .then_with(|| left.scheme_index.cmp(&right.scheme_index))
            .then_with(|| left.aid_index.cmp(&right.aid_index))
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{load_profile_set, BuildMode, ConfigLoadPolicy, SignatureStatus};
    use crate::restrictions::EmvDate;

    const PROFILE: &[u8] = include_bytes!("../docs/scheme_profiles.cert.json");

    fn profiles() -> ProfileSet {
        load_profile_set(
            PROFILE,
            &ConfigLoadPolicy {
                mode: BuildMode::Certification,
                signature_status: SignatureStatus::Verified,
                installed_version: 1,
                candidate_version: 2,
                evaluation_date: EmvDate {
                    year: 26,
                    month: 5,
                    day: 21,
                },
            },
        )
        .unwrap()
    }

    #[test]
    fn extracts_candidate_aids_from_directory_fci() {
        assert_eq!(
            parse_fci_candidate_aids(&[0x4f, 0x07, 0xa0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10])
                .unwrap_err(),
            KernelError::MissingMandatoryTag
        );

        let fci = [0x6f, 0x07, 0xa5, 0x05, 0xbf, 0x0c, 0x02, 0x4f, 0x00];
        assert_eq!(
            parse_fci_candidate_aids(&fci).unwrap(),
            Vec::<Vec<u8>>::new()
        );

        let fci = [
            0x6f, 0x09, 0xa5, 0x07, 0xbf, 0x0c, 0x04, 0x61, 0x02, 0x4f, 0x00,
        ];
        assert_eq!(
            parse_fci_candidate_aids(&fci).unwrap_err(),
            KernelError::InvalidProfile
        );

        let fci = [
            0x6f, 0x0a, 0xa5, 0x08, 0xbf, 0x0c, 0x05, 0x4f, 0x03, 0xa0, 0x00, 0x00,
        ];
        assert_eq!(
            parse_fci_candidate_aids(&fci).unwrap(),
            Vec::<Vec<u8>>::new()
        );

        let fci = [
            0x6f, 0x1b, 0xa5, 0x19, 0xbf, 0x0c, 0x16, 0x61, 0x09, 0x4f, 0x07, 0xa0, 0x00, 0x00,
            0x00, 0x03, 0x10, 0x10, 0x61, 0x09, 0x4f, 0x07, 0xa0, 0x00, 0x00, 0x00, 0x04, 0x10,
            0x10,
        ];
        assert_eq!(
            parse_fci_candidate_aids(&fci).unwrap(),
            vec![
                vec![0xa0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10],
                vec![0xa0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x10],
            ]
        );
    }

    #[test]
    fn rejects_duplicate_adf_names_in_directory_entries() {
        let fci = [
            0x6f, 0x17, 0xa5, 0x15, 0xbf, 0x0c, 0x12, 0x61, 0x10, 0x4f, 0x07, 0xa0, 0x00, 0x00,
            0x00, 0x03, 0x10, 0x10, 0x4f, 0x05, 0xa0, 0x00, 0x00, 0x00, 0x03,
        ];
        assert_eq!(
            parse_fci_candidate_aids(&fci).unwrap_err(),
            KernelError::ParseError
        );
    }

    #[test]
    fn selects_deterministically_when_profile_priorities_match() {
        let candidates = match_profile_candidates(
            &profiles(),
            Interface::Contact,
            &[
                vec![0xa0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10],
                vec![0xa0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x10],
            ],
        )
        .unwrap();
        assert_eq!(
            candidates[0].aid,
            vec![0xa0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10]
        );
        assert_eq!(candidates[0].priority, 10);
    }

    #[test]
    fn direct_candidates_are_sorted_by_signed_profile_priority() {
        let candidates = direct_profile_candidates(&profiles(), Interface::Contact).unwrap();
        assert_eq!(candidates.len(), 2);
        assert_eq!(
            candidates[0].aid,
            vec![0xa0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10]
        );
    }
}
