use crate::error::{KernelError, KernelResult};

const PROFILE_HEADER: [&str; 9] = [
    "profile_id",
    "tier",
    "device_class",
    "oda_rsa_us_max",
    "oda_ecc_us_max",
    "tlv_parse_us_max",
    "apdu_overhead_us_max",
    "kernel_only_us_max",
    "test_id",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PerfStage {
    OdaRsa,
    OdaEcc,
    TlvParsing,
    ApduOverhead,
}

impl PerfStage {
    fn index(self) -> usize {
        match self {
            Self::OdaRsa => 0,
            Self::OdaEcc => 1,
            Self::TlvParsing => 2,
            Self::ApduOverhead => 3,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PerfAccumulator {
    elapsed_micros: [u64; 4],
}

impl PerfAccumulator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, stage: PerfStage, elapsed_micros: u64) -> KernelResult<()> {
        let bucket = &mut self.elapsed_micros[stage.index()];
        *bucket = bucket
            .checked_add(elapsed_micros)
            .ok_or(KernelError::LengthOverflow)?;
        Ok(())
    }

    pub fn stage_micros(self, stage: PerfStage) -> u64 {
        self.elapsed_micros[stage.index()]
    }

    pub fn kernel_only_micros(self) -> KernelResult<u64> {
        self.elapsed_micros.iter().try_fold(0u64, |total, value| {
            total.checked_add(*value).ok_or(KernelError::LengthOverflow)
        })
    }

    pub fn within_target(self, target: &PerformanceTarget) -> KernelResult<bool> {
        Ok(
            self.stage_micros(PerfStage::OdaRsa) <= target.oda_rsa_us_max
                && self.stage_micros(PerfStage::OdaEcc) <= target.oda_ecc_us_max
                && self.stage_micros(PerfStage::TlvParsing) <= target.tlv_parse_us_max
                && self.stage_micros(PerfStage::ApduOverhead) <= target.apdu_overhead_us_max
                && self.kernel_only_micros()? <= target.kernel_only_us_max,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PerformanceTarget {
    pub profile_id: String,
    pub tier: String,
    pub device_class: String,
    pub oda_rsa_us_max: u64,
    pub oda_ecc_us_max: u64,
    pub tlv_parse_us_max: u64,
    pub apdu_overhead_us_max: u64,
    pub kernel_only_us_max: u64,
    pub test_id: String,
}

pub fn parse_performance_profile(csv: &str) -> KernelResult<Vec<PerformanceTarget>> {
    let mut lines = csv.lines();
    let header = lines.next().ok_or(KernelError::ParseError)?;
    let header_fields = header.split(',').collect::<Vec<_>>();
    if header_fields.as_slice() != PROFILE_HEADER.as_slice() {
        return Err(KernelError::ParseError);
    }

    let mut targets = Vec::new();
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let fields = line.split(',').collect::<Vec<_>>();
        if fields.len() != PROFILE_HEADER.len() || fields.iter().any(|field| field.is_empty()) {
            return Err(KernelError::ParseError);
        }
        if fields[2].contains("profile-defined") || fields[2].contains("generic") {
            return Err(KernelError::InvalidProfile);
        }
        let target = PerformanceTarget {
            profile_id: fields[0].to_string(),
            tier: fields[1].to_string(),
            device_class: fields[2].to_string(),
            oda_rsa_us_max: parse_positive_u64(fields[3])?,
            oda_ecc_us_max: parse_positive_u64(fields[4])?,
            tlv_parse_us_max: parse_positive_u64(fields[5])?,
            apdu_overhead_us_max: parse_positive_u64(fields[6])?,
            kernel_only_us_max: parse_positive_u64(fields[7])?,
            test_id: fields[8].to_string(),
        };
        if !target.test_id.contains("KRN-PERF-001") || !target.test_id.contains("KRN-PERF-002") {
            return Err(KernelError::InvalidProfile);
        }
        targets.push(target);
    }

    if targets.is_empty() {
        return Err(KernelError::InvalidProfile);
    }
    Ok(targets)
}

fn parse_positive_u64(value: &str) -> KernelResult<u64> {
    let parsed = value.parse::<u64>().map_err(|_| KernelError::ParseError)?;
    if parsed == 0 {
        return Err(KernelError::InvalidProfile);
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PERFORMANCE_PROFILE: &str = include_str!("../docs/performance_profile.csv");

    #[test]
    fn records_oda_crypto_tlv_and_apdu_buckets_separately() {
        let mut perf = PerfAccumulator::new();
        perf.record(PerfStage::OdaRsa, 7).unwrap();
        perf.record(PerfStage::OdaEcc, 11).unwrap();
        perf.record(PerfStage::TlvParsing, 3).unwrap();
        perf.record(PerfStage::ApduOverhead, 5).unwrap();
        perf.record(PerfStage::OdaRsa, 13).unwrap();

        assert_eq!(perf.stage_micros(PerfStage::OdaRsa), 20);
        assert_eq!(perf.stage_micros(PerfStage::OdaEcc), 11);
        assert_eq!(perf.stage_micros(PerfStage::TlvParsing), 3);
        assert_eq!(perf.stage_micros(PerfStage::ApduOverhead), 5);
        assert_eq!(perf.kernel_only_micros().unwrap(), 39);

        let target = &parse_performance_profile(PERFORMANCE_PROFILE).unwrap()[0];
        assert!(perf.within_target(target).unwrap());
    }

    #[test]
    fn rejects_performance_counter_overflow() {
        let mut stage_overflow = PerfAccumulator::new();
        stage_overflow.record(PerfStage::OdaRsa, u64::MAX).unwrap();
        assert_eq!(
            stage_overflow.record(PerfStage::OdaRsa, 1).unwrap_err(),
            KernelError::LengthOverflow
        );

        let mut total_overflow = PerfAccumulator::new();
        total_overflow.record(PerfStage::OdaRsa, u64::MAX).unwrap();
        total_overflow.record(PerfStage::TlvParsing, 1).unwrap();
        assert_eq!(
            total_overflow.kernel_only_micros().unwrap_err(),
            KernelError::LengthOverflow
        );
        let permissive_target = PerformanceTarget {
            profile_id: "overflow-harness".to_string(),
            tier: "test".to_string(),
            device_class: "test harness".to_string(),
            oda_rsa_us_max: u64::MAX,
            oda_ecc_us_max: u64::MAX,
            tlv_parse_us_max: u64::MAX,
            apdu_overhead_us_max: u64::MAX,
            kernel_only_us_max: u64::MAX,
            test_id: "KRN-PERF-001;KRN-PERF-002".to_string(),
        };
        assert_eq!(
            total_overflow
                .within_target(&permissive_target)
                .unwrap_err(),
            KernelError::LengthOverflow
        );
    }

    #[test]
    fn validates_product_performance_profile_targets() {
        let targets = parse_performance_profile(PERFORMANCE_PROFILE).unwrap();
        assert_eq!(targets.len(), 2);
        assert!(targets
            .iter()
            .all(|target| target.profile_id.starts_with("hyperion-mp35p")));
        assert!(targets
            .iter()
            .all(|target| target.test_id.contains("KRN-PERF-001;KRN-PERF-002")));

        let generic = PERFORMANCE_PROFILE.replace(
            "Hyperion MP35P contact kernel",
            "generic platform-profile-defined",
        );
        assert_eq!(
            parse_performance_profile(&generic).unwrap_err(),
            KernelError::InvalidProfile
        );

        let missing_target = PERFORMANCE_PROFILE.replace(",20000,30000,", ",0,30000,");
        assert_eq!(
            parse_performance_profile(&missing_target).unwrap_err(),
            KernelError::InvalidProfile
        );
    }

    #[test]
    fn rejects_malformed_or_incomplete_performance_profiles() {
        assert_eq!(
            parse_performance_profile("").unwrap_err(),
            KernelError::ParseError
        );
        assert_eq!(
            parse_performance_profile("wrong,header\n").unwrap_err(),
            KernelError::ParseError
        );
        assert_eq!(
            parse_performance_profile(PROFILE_HEADER.join(",").as_str()).unwrap_err(),
            KernelError::InvalidProfile
        );

        let header = PROFILE_HEADER.join(",");
        let missing_field = format!("{header}\np,certified,test device,1,2,3,4,5\n");
        assert_eq!(
            parse_performance_profile(&missing_field).unwrap_err(),
            KernelError::ParseError
        );

        let empty_field =
            format!("{header}\np,certified,test device,1,2,,4,5,KRN-PERF-001;KRN-PERF-002\n");
        assert_eq!(
            parse_performance_profile(&empty_field).unwrap_err(),
            KernelError::ParseError
        );

        let non_numeric =
            format!("{header}\np,certified,test device,NaN,2,3,4,5,KRN-PERF-001;KRN-PERF-002\n");
        assert_eq!(
            parse_performance_profile(&non_numeric).unwrap_err(),
            KernelError::ParseError
        );

        let missing_traceability =
            format!("{header}\np,certified,test device,1,2,3,4,5,KRN-PERF-001\n");
        assert_eq!(
            parse_performance_profile(&missing_traceability).unwrap_err(),
            KernelError::InvalidProfile
        );
    }
}
