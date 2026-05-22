use crate::apdu::{Interface, MAX_AID_LEN, MIN_AID_LEN};
use crate::config::ProfileSet;
use crate::error::{KernelError, KernelResult};
use crate::tlv;

pub const MAX_CANDIDATE_AIDS: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectionCandidate {
    /// Signed profile AID used to locate the certified scheme/profile rules.
    pub aid: Vec<u8>,
    /// ADF name to send in the final SELECT command.
    ///
    /// For exact matches this is the same as `aid`. For partial-selection
    /// profile matches it preserves the card directory's full ADF name so the
    /// final SELECT does not silently shorten the card-provided candidate.
    pub select_aid: Vec<u8>,
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
                if out.len() >= MAX_CANDIDATE_AIDS {
                    return Err(KernelError::LengthOverflow);
                }
                out.push(SelectionCandidate {
                    aid: aid.aid.clone(),
                    select_aid: aid.aid.clone(),
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
    reject_duplicate_card_candidates(card_candidates)?;

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
            for card_aid in card_candidates
                .iter()
                .filter(|card| aid_matches(card, &aid.aid, aid.partial_selection))
            {
                if out.len() >= MAX_CANDIDATE_AIDS {
                    return Err(KernelError::LengthOverflow);
                }
                out.push(SelectionCandidate {
                    aid: aid.aid.clone(),
                    select_aid: card_aid.clone(),
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

fn reject_duplicate_card_candidates(card_candidates: &[Vec<u8>]) -> KernelResult<()> {
    for (index, candidate) in card_candidates.iter().enumerate() {
        if card_candidates[..index]
            .iter()
            .any(|prior| prior == candidate)
        {
            return Err(KernelError::ParseError);
        }
    }
    Ok(())
}

fn push_unique_aid(out: &mut Vec<Vec<u8>>, aid: &[u8]) -> KernelResult<()> {
    if !(MIN_AID_LEN..=MAX_AID_LEN).contains(&aid.len()) {
        return Err(KernelError::InvalidProfile);
    }
    if out.len() >= MAX_CANDIDATE_AIDS {
        return Err(KernelError::LengthOverflow);
    }
    if out.iter().any(|stored| stored == aid) {
        return Err(KernelError::ParseError);
    }
    out.push(aid.to_vec());
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
            .then_with(|| left.select_aid.cmp(&right.select_aid))
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
    fn rejects_duplicate_adf_names_across_directory_entries() {
        let fci = [
            0x6f, 0x1b, 0xa5, 0x19, 0xbf, 0x0c, 0x16, 0x61, 0x09, 0x4f, 0x07, 0xa0, 0x00, 0x00,
            0x00, 0x03, 0x10, 0x10, 0x61, 0x09, 0x4f, 0x07, 0xa0, 0x00, 0x00, 0x00, 0x03, 0x10,
            0x10,
        ];
        assert_eq!(
            parse_fci_candidate_aids(&fci).unwrap_err(),
            KernelError::ParseError
        );
    }

    #[test]
    fn rejects_candidate_aid_lists_above_limit() {
        let mut directory_entries = Vec::new();
        for index in 0..=MAX_CANDIDATE_AIDS {
            let aid = [0xa0, 0x00, 0x00, 0x00, 0x03, 0x10, index as u8];
            directory_entries.extend_from_slice(&tlv_bytes(&[0x61], &tlv_bytes(&[0x4f], &aid)));
        }
        let fci = tlv_bytes(
            &[0x6f],
            &tlv_bytes(&[0xa5], &tlv_bytes(&[0xbf, 0x0c], &directory_entries)),
        );

        assert_eq!(
            parse_fci_candidate_aids(&fci).unwrap_err(),
            KernelError::LengthOverflow
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
    fn partial_selection_preserves_card_adf_name_for_final_select() {
        let mut profiles = profiles();
        profiles.schemes[0].aids[0].aid = vec![0xa0, 0x00, 0x00, 0x00, 0x03];
        profiles.schemes[0].aids[0].partial_selection = true;

        let candidates = match_profile_candidates(
            &profiles,
            Interface::Contact,
            &[vec![0xa0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10]],
        )
        .unwrap();

        assert_eq!(candidates[0].aid, vec![0xa0, 0x00, 0x00, 0x00, 0x03]);
        assert_eq!(
            candidates[0].select_aid,
            vec![0xa0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10]
        );
    }

    #[test]
    fn partial_selection_retains_all_matching_card_adf_names() {
        let mut profiles = profiles();
        profiles.schemes[0].aids[0].aid = vec![0xa0, 0x00, 0x00, 0x00, 0x03];
        profiles.schemes[0].aids[0].partial_selection = true;

        let candidates = match_profile_candidates(
            &profiles,
            Interface::Contact,
            &[
                vec![0xa0, 0x00, 0x00, 0x00, 0x03, 0x20, 0x20],
                vec![0xa0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10],
            ],
        )
        .unwrap();

        assert_eq!(candidates.len(), 2);
        assert!(candidates
            .iter()
            .all(|candidate| candidate.aid == vec![0xa0, 0x00, 0x00, 0x00, 0x03]));
        assert_eq!(
            candidates
                .iter()
                .map(|candidate| candidate.select_aid.as_slice())
                .collect::<Vec<_>>(),
            vec![
                &[0xa0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10][..],
                &[0xa0, 0x00, 0x00, 0x00, 0x03, 0x20, 0x20][..],
            ]
        );
    }

    #[test]
    fn rejects_duplicate_card_candidates_before_profile_matching() {
        assert_eq!(
            match_profile_candidates(
                &profiles(),
                Interface::Contact,
                &[
                    vec![0xa0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10],
                    vec![0xa0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10],
                ],
            )
            .unwrap_err(),
            KernelError::ParseError
        );
    }

    #[test]
    fn direct_candidates_are_sorted_by_signed_profile_priority() {
        let candidates = direct_profile_candidates(&profiles(), Interface::Contact).unwrap();
        assert_eq!(candidates.len(), 2);
        assert_eq!(
            candidates[0].aid,
            vec![0xa0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10]
        );
        assert_eq!(candidates[0].select_aid, candidates[0].aid);
    }

    #[test]
    fn rejects_direct_profile_candidates_above_limit() {
        let mut profiles = profiles();
        let template = profiles.schemes[0].aids[0].clone();
        profiles.schemes[0].aids.clear();
        for index in 0..=MAX_CANDIDATE_AIDS {
            let mut aid = template.clone();
            aid.aid = vec![0xa0, 0x00, 0x00, 0x00, 0x03, 0x20, index as u8];
            aid.interfaces = vec!["contact".to_string()];
            profiles.schemes[0].aids.push(aid);
        }

        assert_eq!(
            direct_profile_candidates(&profiles, Interface::Contact).unwrap_err(),
            KernelError::LengthOverflow
        );
    }

    fn tlv_bytes(tag: &[u8], value: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(tag);
        encode_len(value.len(), &mut out);
        out.extend_from_slice(value);
        out
    }

    fn encode_len(len: usize, out: &mut Vec<u8>) {
        if len < 0x80 {
            out.push(len as u8);
        } else if len <= 0xff {
            out.extend_from_slice(&[0x81, len as u8]);
        } else {
            out.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]);
        }
    }
}
