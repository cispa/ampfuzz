use crate::executor::StatusType;
use angora_common::{config::BRANCHES_SIZE, shm::SHM};
use std::{
    self,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, RwLock,
    },
};
#[cfg(feature = "unstable")]
use std::intrinsics::unlikely;

use crate::dyncfg::cfg::{ControlFlowGraph, CmpId};
use crate::byte_count::AmpByteCount;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use itertools::Itertools;

use serde_json::json;

pub type BranchBuf = [u8; BRANCHES_SIZE];
#[cfg(target_pointer_width = "32")]
type BranchEntry = u32;
#[cfg(target_pointer_width = "64")]
type BranchEntry = u64;

#[cfg(target_pointer_width = "32")]
const ENTRY_SIZE: usize = 4;
#[cfg(target_pointer_width = "64")]
const ENTRY_SIZE: usize = 8;

type BranchBufPlus = [BranchEntry; BRANCHES_SIZE / ENTRY_SIZE];
pub type BitmapHash = u64;

pub type PathAmplification = std::collections::HashMap::<BitmapHash, AmpByteCount>;

pub trait JsonStr {
    fn to_json(&self) -> String;
}

impl JsonStr for PathAmplification {
    fn to_json(&self) -> String {
        format!("[{}]", self.iter().map(|(path, amp)| json!({
                                "path": &format!("{:x}", path),
                                "factor": amp.as_factor(),
                                "bytes_in": amp.bytes_in.l7,
                                "bytes_out": amp.bytes_out.l7
            }).to_string()).join(","))
    }
}

// Map of bit bucket
// [1], [2], [3], [4, 7], [8, 15], [16, 31], [32, 127], [128, infinity]
static COUNT_LOOKUP: [u8; 256] = [
    0, 1, 2, 4, 8, 8, 8, 8, 16, 16, 16, 16, 16, 16, 16, 16, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
    32, 32, 32, 32, 32, 32, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
];

macro_rules! cast {
    ($ptr:expr) => {{
        unsafe { std::mem::transmute($ptr) }
    }};
}

pub struct GlobalBranches {
    virgin_branches: RwLock<Box<BranchBuf>>,
    tmouts_branches: RwLock<Box<BranchBuf>>,
    crashes_branches: RwLock<Box<BranchBuf>>,
    density: AtomicUsize,
    path_amplification: RwLock<PathAmplification>,
    max_amplification: RwLock<AmpByteCount>,
    cfg: RwLock<ControlFlowGraph>,
}

impl GlobalBranches {
    pub fn new(cfg: RwLock<ControlFlowGraph>) -> Self {
        Self {
            virgin_branches: RwLock::new(Box::new([255u8; BRANCHES_SIZE])),
            tmouts_branches: RwLock::new(Box::new([255u8; BRANCHES_SIZE])),
            crashes_branches: RwLock::new(Box::new([255u8; BRANCHES_SIZE])),
            density: AtomicUsize::new(0),
            path_amplification: RwLock::new(PathAmplification::new()),
            max_amplification: RwLock::new(AmpByteCount::default()),
            cfg,
        }
    }

    pub fn get_density(&self) -> f32 {
        let d = self.density.load(Ordering::Relaxed);
        (d * 10000 / BRANCHES_SIZE) as f32 / 100.0
    }
}

pub struct Branches {
    global: Arc<GlobalBranches>,
    trace: SHM<BranchBuf>,
}

impl Branches {
    pub fn new(global: Arc<GlobalBranches>) -> Self {
        let trace = SHM::<BranchBuf>::new();
        Self { global, trace }
    }

    pub fn clear_trace(&mut self) {
        self.trace.clear();
    }

    pub fn get_id(&self) -> i32 {
        self.trace.get_id()
    }

    pub fn get_path_as_hash(&self) -> BitmapHash {
        let path: Vec<usize> = self.get_path().into_iter().map(|(idx, count)| idx).collect();
        let mut def_hasher = DefaultHasher::new();
        Hash::hash_slice(&path, &mut def_hasher);
        let exec_path_hash = def_hasher.finish();
        exec_path_hash
    }

    fn get_path(&self) -> Vec<(usize, u8)> {
        let mut path = Vec::<(usize, u8)>::new();
        let buf_plus: &BranchBufPlus = cast!(&*self.trace);
        let buf: &BranchBuf = &*self.trace;
        for (i, &v) in buf_plus.iter().enumerate() {
            macro_rules! run_loop { () => {{
                let base = i * ENTRY_SIZE;
                for j in 0..ENTRY_SIZE {
                    let idx = base + j;
                    let new_val = buf[idx];
                    if new_val > 0 {
                        path.push((idx, COUNT_LOOKUP[new_val as usize]))
                    }
                }
            }}}
            #[cfg(feature = "unstable")]
                {
                    if unsafe { unlikely(v > 0) } {
                        run_loop!()
                    }
                }
            #[cfg(not(feature = "unstable"))]
                {
                    if v > 0 {
                        run_loop!()
                    }
                }
        }
        // debug!("count branch table: {}", path.len());
        path
    }

    pub fn has_new(&mut self, status: &StatusType, directed: bool) -> (bool, bool, usize, bool) {
        let gb_map = match status {
            StatusType::Normal => &self.global.virgin_branches,
            StatusType::Timeout => &self.global.tmouts_branches,
            StatusType::Crash => &self.global.crashes_branches,
            StatusType::Amp(_, _) => &self.global.virgin_branches, // TODO: Introduce separate branches for amps?
            StatusType::Skip | StatusType::Error => {
                return (false, false, 0, false);
            }
        };
        let path = self.get_path();
        let edge_num = path.len();

        let mut to_write = vec![]; // New entries that should be written back to the corresponding global map
        let mut has_new_edge = false;
        let mut num_new_edge = 0;
        let mut has_good_amp = false;

        {
            // read only
            let gb_map_read = gb_map.read().unwrap();
            for &br in &path {
                let gb_v = gb_map_read[br.0];

                // 255 = 0xff = 0b11111111 is the default value in gb_map.
                // The i-th bit is removed when a path is found that hits the
                // corresponding entry (1<<(i-1))+1 to (1<<i) times
                if gb_v == 255u8 {
                    num_new_edge += 1;
                }

                // if the current hit-count is still "set" in the global map, create an updated
                // entry that removes the given bit (by AND-ing with the bitwise complement)
                if (br.1 & gb_v) > 0 {
                    to_write.push((br.0, gb_v & (!br.1)));
                }
            }
        }

        if num_new_edge > 0 {
            if matches!(status, StatusType::Normal|StatusType::Amp(_,_)) {
                // only count virgin branches
                self.global
                    .density
                    .fetch_add(num_new_edge, Ordering::Relaxed);
            }
            has_new_edge = true;
        }

        if let StatusType::Amp(path, amp) = status {
            let mut best_amp = self.global.max_amplification.write().unwrap();
            let mut path_amps = self.global.path_amplification.write().unwrap();
            let path_amp_entry = path_amps.entry(path.clone());

            // Amp is interesting, if it was achieved on a new path...
            has_good_amp = has_new_edge;

            //  ...or provides a better factor globally...
            if amp > &best_amp {
                *best_amp = amp.clone();
                has_good_amp = true;
            }

            // ... or locally
            path_amp_entry.and_modify(|old| {
                if amp > old {
                    *old = amp.clone();
                    has_good_amp = true;
                }
            }).or_insert_with(|| amp.clone());
        }


        /*
        for (a, b) in to_write.clone().into_iter().tuple_windows() {
            let mut dyncfg = self.global.cfg.write().unwrap();
            let edge = (a.0, b.0);
            dyncfg.add_bb_edge(edge);
        }
        */

        if to_write.is_empty() {
            return (false, false, edge_num, has_good_amp);
        }

        {
            // write
            let mut gb_map_write = gb_map.write().unwrap();
            for &br in &to_write {
                gb_map_write[br.0] = br.1;
            }
        }

        // has_new_directed_edge will be set to `true`, if any of the traversed CFG-locations
        // (= those where we just updated the global map) can reach any of our targets in the CFG
        let mut has_new_directed_edge = false;
        for &br in &to_write {
            let dyncfg = self.global.cfg.read().unwrap();
            if dyncfg.has_path_to_target(br.0 as CmpId) {
                has_new_directed_edge = true;
                break;
            }
        }

        //(has_new_directed_edge, has_new_edge, edge_num)
        // read as (has_new_path, _has_new_edge, edge_num, has_good_amp)
        (if !directed { true } else { has_new_directed_edge }, has_new_edge, edge_num, has_good_amp)
    }
}

impl std::fmt::Debug for Branches {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "")
    }
}
