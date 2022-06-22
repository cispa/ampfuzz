use crate::{cond_stmt_base::CondStmtBase, tag::TagSeg};
use serde_derive::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::ffi::CString;

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct LogData {
    pub cond_list: Vec<CondStmtBase>,
    pub tags: HashMap<u32, Vec<TagSeg>>,
    pub magic_bytes: HashMap<usize, (Vec<u8>, Vec<u8>)>,
    pub load_paths: HashSet<CString>,
}

impl LogData {
    pub fn new() -> Self {
        Self {
            cond_list: vec![],
            tags: HashMap::new(),
            magic_bytes: HashMap::new(),
            load_paths: HashSet::new(),
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub enum LogMsg {
    Tag { lb: u32, tag: Vec<TagSeg> },
    MagicBytes { i: usize, bytes: (Vec<u8>, Vec<u8>) },
    Cond { cond: CondStmtBase },
    Load { path: CString },
}