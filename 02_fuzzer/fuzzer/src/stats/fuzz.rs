use super::*;
use crate::cond_stmt::CondStmt;
use serde_derive::Serialize;
use crate::byte_count::AmpByteCount;
use crate::branches::PathAmplification;

#[derive(Clone, Default, Serialize)]
pub struct StrategyStats {
    pub time: TimeDuration,
    pub num_conds: Counter,
    pub num_exec: Counter,
    pub num_inputs: Counter,
    pub num_hangs: Counter,
    pub num_crashes: Counter,
    pub num_amps: Counter,
    pub best_amp: AmpByteCount,
    pub path_amplification: PathAmplification,
    pub best_path_amp: AmpByteCount,
}

impl fmt::Display for StrategyStats {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "CONDS: {}, EXEC: {}, TIME: {}, FOUND: {} - {} - {} - {}",
            self.num_conds,
            self.num_exec,
            self.time,
            self.num_inputs,
            self.num_hangs,
            self.num_crashes,
            self.num_amps,
        )
    }
}

#[derive(Clone, Default, Serialize)]
pub struct FuzzStats([StrategyStats; fuzz_type::FUZZ_TYPE_NUM]);

impl FuzzStats {
    #[inline]
    pub fn get_mut(&mut self, i: usize) -> &mut StrategyStats {
        assert!(i < fuzz_type::FUZZ_TYPE_NUM);
        &mut self.0[i]
    }

    pub fn get(&self, i: usize) -> &StrategyStats {
        assert!(i < fuzz_type::FUZZ_TYPE_NUM);
        &self.0[i]
    }

    pub fn clear(&mut self) {
        for s in self.0.iter_mut() {
            s.num_conds = Default::default();
        }
    }

    pub fn count(&mut self, cond: &CondStmt) {
        self.0[cond.get_fuzz_type().index()].num_conds.count();
    }

    pub fn may_be_model_failure(&self) -> bool {
        self.0[fuzz_type::FuzzType::ExploreFuzz.index()].num_conds.0 + 1
            < (self.0[fuzz_type::FuzzType::AFLFuzz.index()].num_conds.0
            + self.0[fuzz_type::FuzzType::OtherFuzz.index()].num_conds.0)
    }

    pub fn mini_log_hdr(&self) -> Vec<String> {
        let mut hdr: Vec<String> = Vec::new();
        for (i, _) in self.0.iter().enumerate() {
            let toplabel = fuzz_type::get_fuzz_type_name(i).to_uppercase();
            hdr.push(format!("{} conds", toplabel));
            hdr.push(format!("{} execs", toplabel))
        }
        return hdr;
    }

    pub fn mini_log(&self) -> Vec<String> {
        let mut row: Vec<String> = Vec::new();
        for s in self.0.iter() {
            row.push(s.num_conds.0.to_string());
            row.push(s.num_exec.0.to_string());
        }
        return row;
    }
}

impl fmt::Display for FuzzStats {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let contents = self
            .0
            .iter()
            .enumerate()
            .map(|(i, s)| {
                format!(
                    "  {:>8} | {}",
                    fuzz_type::get_fuzz_type_name(i).to_uppercase(),
                    s
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        write!(f, "{}", contents)
    }
}
