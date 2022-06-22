use super::CondState;
use crate::fuzz_type::FuzzType;
use angora_common::{cond_stmt_base::CondStmtBase, defs, tag::TagSeg};
use std::hash::{Hash, Hasher};

#[derive(Debug, Default, Clone,Serialize)]
pub struct CondStmt {
    pub base: CondStmtBase,
    pub offsets: Vec<TagSeg>,
    pub offsets_opt: Vec<TagSeg>,
    pub variables: Vec<u8>,

    pub speed: u32,
    pub is_desirable: bool, // non-convex
    pub is_consistent: bool,
    pub is_target: bool, // ParmeSan target
    pub fuzz_times: usize,
    pub state: CondState,
    pub num_minimal_optima: usize,
    pub linear: bool,
}

impl PartialEq for CondStmt {
    fn eq(&self, other: &CondStmt) -> bool {
        self.base == other.base
    }
}

impl Eq for CondStmt {}

impl Hash for CondStmt {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.base.cmpid.hash(state);
        self.base.context.hash(state);
        self.base.order.hash(state);
    }
}

impl CondStmt {
    pub fn new() -> Self {
        let cond_base = Default::default();
        Self {
            base: cond_base,
            offsets: vec![],
            offsets_opt: vec![],
            //ind_offsets: vec![], 
            variables: vec![],
            speed: 0,
            is_consistent: true,
            is_desirable: true,
            is_target: false,
            fuzz_times: 0,
            state: CondState::default(),
            num_minimal_optima: 0,
            linear: false,
        }
    }

    pub fn from(cond_base: CondStmtBase) -> Self {
        let mut cond = Self::new();
        cond.base = cond_base;
        cond
    }

    pub fn get_fuzz_type(&self) -> FuzzType {
        match self.base.op {
            defs::COND_AFL_OP => FuzzType::AFLFuzz,
            defs::COND_LEN_OP => FuzzType::LenFuzz,
            defs::COND_FN_OP => FuzzType::CmpFnFuzz,
            defs::COND_AMP_OP => FuzzType::AmpFuzz,
            _ => {
                if self.base.is_explore() {
                    FuzzType::ExploreFuzz
                } else if self.base.is_exploitable() {
                    FuzzType::ExploitFuzz
                } else {
                    FuzzType::OtherFuzz
                }
            },
        }
    }

    pub fn is_tainted(&self) -> bool {
        self.offsets.len() > 0
    }

    pub fn is_bool(&self) -> bool {
        (self.base.may_be_bool() && !self.is_desirable) || (self.base.op & defs::COND_BOOL_MASK) > 0
    }

    pub fn mark_as_done(&mut self) {
        self.base.condition = defs::COND_DONE_ST;
        self.clear();
    }

    pub fn set_target(&mut self, b: bool) {
        self.is_target = b;
    }

    pub fn clear(&mut self) {
        self.offsets = vec![];
        self.offsets_opt = vec![];
        self.variables = vec![];
    }

    pub fn is_discarded(&self) -> bool {
        self.is_done() || self.state.is_unsolvable() || self.state.is_timeout()
    }

    pub fn is_first_time(&self) -> bool {
        self.fuzz_times == 1
    }

    pub fn get_afl_cond(id: usize, speed: u32, edge_num: usize) -> Self {
        let mut afl_cond = Self::new();
        afl_cond.speed = speed;
        afl_cond.base.op = defs::COND_AFL_OP;
        afl_cond.base.cmpid = id as u32;
        afl_cond.base.belong = id as u32; // keep link to original input
        afl_cond.base.context = 0;
        afl_cond.base.order = 0;
        afl_cond.base.arg1 = edge_num as u64;
        afl_cond
    }

    pub fn get_amp_cond(id: usize) -> Self {
        let mut amp_cond = Self::new();
        amp_cond.base.op = defs::COND_AMP_OP;
        amp_cond.base.cmpid = id as u32;
        amp_cond.base.belong = id as u32; // keep link to original input
        amp_cond
    }

    pub fn is_done(&self) -> bool {
        self.base.is_done()
    }
}
