use super::*;
use crate::{cond_stmt::CondStmt, executor::StatusType};
use crate::dyncfg::cfg::ControlFlowGraph;
use rand;
use std::{
    fs,
    io::prelude::*,
    mem,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex, RwLock,
    },
};

use md5::{Md5, Digest};
// https://crates.io/crates/priority-queue
use angora_common::config;
use priority_queue::PriorityQueue;
use crate::byte_count::AmpByteCount;
use crate::branches::BitmapHash;

pub struct Depot {
    pub queue: Mutex<PriorityQueue<CondStmt, QPriority>>,
    pub num_inputs: AtomicUsize,
    pub num_hangs: AtomicUsize,
    pub num_crashes: AtomicUsize,
    pub num_amps: AtomicUsize,
    pub dirs: DepotDir,
    pub cfg: RwLock<ControlFlowGraph>,
}

impl Depot {
    pub fn new(in_dir: PathBuf, out_dir: &Path, cfg: RwLock<ControlFlowGraph>) -> Self {
        Self {
            queue: Mutex::new(PriorityQueue::new()),
            num_inputs: AtomicUsize::new(0),
            num_hangs: AtomicUsize::new(0),
            num_crashes: AtomicUsize::new(0),
            num_amps: AtomicUsize::new(0),
            dirs: DepotDir::new(in_dir, out_dir),
            cfg,
        }
    }

    fn save_input(
        status: &StatusType,
        buf: &Vec<u8>,
        num: &AtomicUsize,
        cmpid: u32,
        dir: &Path,
    ) -> usize {
        let id = num.fetch_add(1, Ordering::Relaxed);
        trace!(
            "Find {} th new {:?} input by fuzzing {}.",
            id,
            status,
            cmpid
        );
        let new_path = get_file_name(dir, id);
        let mut f = fs::File::create(new_path.as_path()).expect("Could not save new input file.");
        f.write_all(buf)
            .expect("Could not write seed buffer to file.");
        f.flush().expect("Could not flush file I/O.");
        id
    }

    fn save_amp(path: &BitmapHash, amp: &AmpByteCount, buf: &Vec<u8>, num: &AtomicUsize, dir: &Path) -> bool {
        let mut hasher = Md5::new();
        hasher.update(buf);
        let md5sum = hasher.finalize();

        //let mut def_hasher = DefaultHasher::new();
        //Hash::hash_slice(&path, &mut def_hasher);
        //let exec_path_hash = def_hasher.finish();
        // TODO: use new multi-layer counts
        let file_name = format!("amp_{:06.2}_{:x}_{:x}", amp.as_factor(), path, md5sum);
        let new_path = dir.join(file_name);
        if new_path.exists() {
            return false;
        }
        num.fetch_add(1, Ordering::Relaxed);
        let mut f = fs::File::create(new_path.as_path()).expect("Could not save new input file.");
        f.write_all(buf)
            .expect("Could not write seed buffer to file.");
        f.flush().expect("Could not flush file I/O.");
        true
    }

    pub fn save(&self, status: &StatusType, buf: &Vec<u8>, cmpid: u32) -> usize {
        match status {
            StatusType::Normal => {
                Self::save_input(&status, buf, &self.num_inputs, cmpid, &self.dirs.inputs_dir)
            }
            StatusType::Timeout => {
                Self::save_input(&status, buf, &self.num_hangs, cmpid, &self.dirs.hangs_dir)
            }
            StatusType::Crash => Self::save_input(
                &status,
                buf,
                &self.num_crashes,
                cmpid,
                &self.dirs.crashes_dir,
            ),
            StatusType::Amp(path, amp) => {
                // save to amps, but also keep as input (for further fuzzing!)
                if Self::save_amp(&path, &amp, buf, &self.num_amps, &self.dirs.amps_dir) {
                    Self::save_input(&StatusType::Normal, buf, &self.num_inputs, cmpid, &self.dirs.inputs_dir)
                } else {
                    // Should we ever end up here? I think not
                    0
                }
            }
            _ => 0, // or here?
        }
    }

    pub fn empty(&self) -> bool {
        self.num_inputs.load(Ordering::Relaxed) == 0
    }

    pub fn next_random(&self) -> usize {
        rand::random::<usize>() % self.num_inputs.load(Ordering::Relaxed)
    }

    pub fn get_input_buf(&self, id: usize) -> Vec<u8> {
        let path = get_file_name(&self.dirs.inputs_dir, id);
        read_from_file(&path)
    }

    pub fn get_entry(&self) -> Option<(CondStmt, QPriority)> {
        let mut q = match self.queue.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("Mutex poisoned! Results may be incorrect. Continuing...");
                poisoned.into_inner()
            }
        };
        q.peek()
            .and_then(|x| Some((x.0.clone(), x.1.clone())))
            .and_then(|x| {
                if !x.1.is_done() {
                    let q_inc = x.1.inc(x.0.base.op);
                    q.change_priority(&(x.0), q_inc);
                }
                Some(x)
            })
    }

    pub fn add_entries(&self, conds: Vec<CondStmt>) {
        let mut q = match self.queue.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("Mutex poisoned! Results may be incorrect. Continuing...");
                poisoned.into_inner()
            }
        };

        for mut cond in conds {
            if cond.is_desirable {
                let cfg = self.cfg.read().unwrap();
                //let distance = cfg.score_for_cmp(cond.base.cmpid);
                let distance = cfg.score_for_cmp_inp(cond.base.cmpid, cond.variables.clone());
                drop(cfg); // No need to hold the lock
                if let Some(v) = q.get_mut(&cond) {
                    if !v.0.is_done() {
                        // If existed one and our new one has two different conditions,
                        // this indicate that it is explored.
                        if v.0.base.condition != cond.base.condition {
                            v.0.mark_as_done();
                            q.change_priority(&cond, QPriority::done());
                        } else {
                            // Existed, but the new one are better
                            // If the cond is faster than the older one, we prefer the faster,
                            if config::PREFER_FAST_COND && v.0.speed > cond.speed {
                                mem::swap(v.0, &mut cond);
                                let priority = QPriority::init_distance(cond.base.op, distance);
                                q.change_priority(&cond, priority);
                            }
                        }
                    }
                } else {
                    let priority = QPriority::init_distance(cond.base.op, distance);
                    q.push(cond, priority);
                }
            }
        }
    }

    pub fn update_entry(&self, cond: CondStmt) {
        let mut q = match self.queue.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("Mutex poisoned! Results may be incorrect. Continuing...");
                poisoned.into_inner()
            }
        };
        if let Some(v) = q.get_mut(&cond) {
            v.0.clone_from(&cond);
            let cfg = self.cfg.read().unwrap();
            let distance = cfg.score_for_cmp(cond.base.cmpid);
            let p = v.1.new_distance(distance);
            q.change_priority(&cond, p);
        } else {
            warn!("Update entry: can not find this cond");
        }
        if cond.is_discarded() {
            q.change_priority(&cond, QPriority::done());
            let mut cfg = self.cfg.write().unwrap();
            cfg.remove_target(cond.base.cmpid);
        }
    }
}
