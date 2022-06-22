use super::*;
use crate::{cond_stmt::CondStmt, executor::StatusType, fuzz_type::FuzzType};
use crate::byte_count::AmpByteCount;
use std::cmp::max;
use crate::branches::{PathAmplification, BitmapHash};
use std::collections::HashSet;

#[derive(Default)]
pub struct LocalStats {
    pub fuzz_type: FuzzType,

    pub num_exec_round: Counter,
    pub num_exec: Counter,
    pub num_inputs: Counter,
    pub num_hangs: Counter,
    pub num_crashes: Counter,
    pub num_amps: Counter, // TODO: maybe remove?

    pub paths: HashSet<BitmapHash>, // set of distinct paths
    pub best_amp: AmpByteCount,
    pub path_amplification: PathAmplification, // map of amplification inducing paths and their best amp-factor
    pub track_time: TimeDuration,
    pub start_time: TimeIns,

    pub avg_exec_time: SyncAverage,
    pub avg_edge_num: SyncAverage,
}

impl LocalStats {
    pub fn register(&mut self, cond: &CondStmt) {
        self.fuzz_type = cond.get_fuzz_type();
        self.clear();
        self.num_exec_round = Default::default();
    }

    pub fn clear(&mut self) {
        self.num_exec = Default::default();
        self.num_inputs = Default::default();
        self.num_hangs = Default::default();
        self.num_crashes = Default::default();
        self.num_amps = Default::default();

        self.best_amp = AmpByteCount::default();
        self.path_amplification = PathAmplification::default();
        self.start_time = Default::default();
        self.track_time = Default::default();
    }

    pub fn find_new(&mut self, status: &StatusType, path_hash: BitmapHash) {
        self.paths.insert(path_hash);
        match status {
            StatusType::Normal => {
                self.num_inputs.count();
            }
            StatusType::Timeout => {
                self.num_hangs.count();
            }
            StatusType::Crash => {
                self.num_crashes.count();
            }
            StatusType::Amp(path, amp) => {
                self.num_amps.count();
                self.best_amp = max(self.best_amp.clone(), amp.clone());
                let path_amps = &mut self.path_amplification;
                path_amps.entry(path.clone()).and_modify(|old| {
                    if old.as_factor() < amp.as_factor() {
                        *old = amp.clone();
                    }
                }).or_insert_with(|| amp.clone());
            }
            _ => {}
        }
    }
}
