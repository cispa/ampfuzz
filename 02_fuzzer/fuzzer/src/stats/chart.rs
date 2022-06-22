use super::*;
use crate::{branches::GlobalBranches, depot::Depot};
use colored::*;
use serde_derive::Serialize;
use std::sync::Arc;
use crate::byte_count::AmpByteCount;
use std::cmp::max;
use crate::fuzz_type::{FuzzType, get_fuzz_type_name};
use crate::cond_stmt::CondStmt;
use crate::branches::{PathAmplification, BitmapHash};
use crate::branches::JsonStr;
use std::collections::HashSet;

#[derive(Default, Serialize)]
pub struct ChartStats {
    init_time: TimeIns,
    track_time: TimeDuration,
    density: Average,

    num_rounds: Counter,
    max_rounds: Counter,
    num_exec: Counter,
    speed: Average,

    avg_exec_time: Average,
    avg_edge_num: Average,

    num_inputs: Counter,
    num_hangs: Counter,
    num_crashes: Counter,
    num_targets: Counter,
    num_amps: Counter,

    paths: HashSet<BitmapHash>,
    best_amp: AmpByteCount,
    path_amplification: PathAmplification,

    fuzz: FuzzStats,
    search: SearchStats,
    state: StateStats,
    fuzz_type: FuzzType,
}

// pub fn merge_hashmaps(map1: &mut std::collections::HashMap::<Vec::<(usize, u8)>, AmpByteCount>, map2: &mut std::collections::HashMap::<Vec::<(usize, u8)>, AmpByteCount>) {
//     for (key, value) in &*map1 {
//         if map2.contains_key(key) {
//             let best_path_amp = map2.get_mut(key).unwrap();
//             if best_path_amp.as_factor() > value.as_factor() {map1[key] = best_path_amp.clone()}
//         }
//     }
//     for (key, value) in &*map2 {
//         if !map1.contains_key(key) {
//             map1[key] = value.clone();
//         }
//     }
// }

pub fn merge_hashmaps(map1: &mut PathAmplification, map2: &PathAmplification) {
    for (path, amp) in &*map2 {
        map1.entry(path.clone()).and_modify(|old| {
            if old.as_factor() < amp.as_factor() {
                *old = amp.clone();
            }
        }).or_insert_with(|| amp.clone());
    }
}

impl ChartStats {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn sync_from_local(&mut self, local: &mut LocalStats) {
        self.track_time += local.track_time;

        local.avg_edge_num.sync(&mut self.avg_edge_num);
        local.avg_exec_time.sync(&mut self.avg_exec_time);

        let st = self.fuzz.get_mut(local.fuzz_type.index());
        st.time += local.start_time.into();
        // st.num_conds.count();

        st.num_exec += local.num_exec;
        self.num_exec += local.num_exec;
        // if has new
        st.num_inputs += local.num_inputs;
        self.num_inputs += local.num_inputs;
        st.num_hangs += local.num_hangs;
        self.num_hangs += local.num_hangs;
        st.num_crashes += local.num_crashes;
        self.num_crashes += local.num_crashes;
        //self.num_targets += local.num_targets;
        st.num_amps += local.num_amps;
        self.num_amps += local.num_amps;

        self.paths.extend(&local.paths);

        st.best_amp = max(st.best_amp.clone(), local.best_amp.clone());
        self.best_amp = max(self.best_amp.clone(), local.best_amp.clone());

        merge_hashmaps(&mut st.path_amplification, &local.path_amplification.clone());
        merge_hashmaps(&mut self.path_amplification, &local.path_amplification.clone());
        //local.clear();
    }

    pub fn finish_round(&mut self) {
        self.num_rounds.count();
    }

    pub fn register(&mut self, cond: &CondStmt) {
        self.fuzz_type = cond.get_fuzz_type();
    }

    pub fn sync_from_global(&mut self, depot: &Arc<Depot>, gb: &Arc<GlobalBranches>) {
        self.get_speed();
        self.iter_pq(depot);
        self.sync_from_branches(gb);
    }

    fn iter_pq(&mut self, depot: &Arc<Depot>) {
        let q = match depot.queue.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("Lock poisoned. Results can be incorrect! Continuing...");
                poisoned.into_inner()
            }
        };
        self.search = Default::default();
        self.state = Default::default();
        self.fuzz.clear();
        let mut max_round = 0;
        for (item, _) in q.iter() {
            if item.fuzz_times > max_round {
                max_round = item.fuzz_times;
            }
            self.fuzz.count(&item);
            if item.base.is_explore() {
                self.search.count(&item);
                self.state.count(&item);
            }
        }
        self.max_rounds = max_round.into();
    }

    fn sync_from_branches(&mut self, gb: &Arc<GlobalBranches>) {
        self.density = Average::new(gb.get_density(), 0);
    }

    fn get_speed(&mut self) {
        let t: TimeDuration = self.init_time.into();
        let d: time::Duration = t.into();
        let ts = d.as_secs() as f64;
        let speed = if ts > 0.0 {
            let v: usize = self.num_exec.into();
            v as f64 / ts
        } else {
            0.0
        };
        self.speed = Average::new(speed as f32, 0);
    }

    pub fn mini_log_hdr(&self) -> Vec<String> {
        let mut hdr = vec!("secs".to_string(),
                           "execs".to_string(),
                           "rounds".to_string(),
                           "density".to_string(),
                           "inputs".to_string(),
                           "hangs".to_string(),
                           "crashes".to_string(),
                           "targets".to_string(),
                           "amp_inputs".to_string(),
                           "paths".to_string(),
                           "amp_paths".to_string(),
                           "best_amp".to_string(),
                           "amps".to_string(),
                           "current_type".to_string());
        hdr.extend(self.fuzz.mini_log_hdr());
        return hdr;
    }

    pub fn mini_log(&self) -> Vec<String> {
        let mut row = vec!(self.init_time.0.elapsed().as_secs().to_string(),
                           self.num_exec.0.to_string(),
                           self.num_rounds.0.to_string(),
                           self.density.0.to_string(),
                           self.num_inputs.0.to_string(),
                           self.num_hangs.0.to_string(),
                           self.num_crashes.0.to_string(),
                           self.num_targets.0.to_string(),
                           self.num_amps.0.to_string(),
                           self.paths.len().to_string(),
                           self.path_amplification.len().to_string(),
                           self.best_amp.as_factor().to_string(),
                           self.path_amplification.to_json(),
                           get_fuzz_type_name(self.fuzz_type.index()),
        );
        row.extend(self.fuzz.mini_log());
        return row;
    }

    pub fn get_explore_num(&self) -> usize {
        self.fuzz
            .get(fuzz_type::FuzzType::ExploreFuzz.index())
            .num_conds
            .into()
    }
}

impl fmt::Display for ChartStats {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.density.0 > 10.0 {
            warn!("Density is too large (> 10%). Please increase `MAP_SIZE_POW2` in and `common/src/config.rs`. Or disable function-call context(density > 50%) by compiling with `ANGORA_CUSTOM_FN_CONTEXT=k` (k is an integer and 0 <= k <= 32) environment variable. Angora disables context if k is 0.");
        }

        if self.search.multiple_inconsist() {
            warn!("Multiple inconsistent warnings. It caused by the fast and track programs has different behaviors. If most constraints are inconsistent, ensure they are compiled with the same environment. Otherwise, please report us.");
            // panic()!
        }

        if self.fuzz.may_be_model_failure() {
            warn!("Find small number constraints, please make sure you have modeled the read functions.")
        }

        write!(
            f,
            r#"
{}
{}
    TIMING |     RUN: {},   TRACK: {}     CURRENT_TYPE: {}
  COVERAGE |    EDGE: {},    DENSITY: {}%
    EXECS  |   TOTAL: {},      ROUND: {},     MAX_R: {}
    SPEED  |  PERIOD: {:6}r/s     TIME: {}us,
    FOUND  |  INPUTS: {},      HANGS: {},   CRASHES: {},   AMPS: {}   (best: {:.2}x, {} -> {})
    PATHS  |   TOTAL: {}       AMPS: {}
{}
{}
{}
{}
{}
{}

"#,
            get_bunny_logo().bold(),
            " -- OVERVIEW -- ".blue().bold(),
            self.init_time,
            self.track_time,
            get_fuzz_type_name(self.fuzz_type.index()),
            self.avg_edge_num,
            self.density,
            self.num_exec,
            self.num_rounds,
            self.max_rounds,
            self.speed,
            self.avg_exec_time,
            self.num_inputs,
            self.num_hangs,
            self.num_crashes,
            self.num_amps,
            self.best_amp.as_factor(),
            usize::from(&self.best_amp.bytes_in),
            usize::from(&self.best_amp.bytes_out),
            self.paths.len(),
            self.path_amplification.len(),
            " -- FUZZ -- ".blue().bold(),
            self.fuzz,
            " -- SEARCH -- ".blue().bold(),
            self.search,
            " -- STATE -- ".blue().bold(),
            self.state,
        )
    }
}
