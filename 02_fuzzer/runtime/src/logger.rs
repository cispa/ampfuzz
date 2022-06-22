use bincode::serialize_into;
use std::{collections::HashMap, env};

use crate::{len_label, tag_set_wrap};
use angora_common::{cond_stmt_base::CondStmtBase, config, defs, log_data::LogData, log_data::LogMsg};
use std::io::Write;
use std::os::raw::c_int;
use std::ffi::CString;
use std::fs::File;
use std::os::unix::io::AsRawFd;

#[derive(Debug)]
pub struct Logger {
    data: LogData,
    track_file: Option<File>,
    order_map: HashMap<(u32, u32), u32>, // (cmpid, context) -> order (= number of hits?)
}

impl Logger {
    pub fn new() -> Self {
        let track_file = match env::var(defs::TRACK_FILE_PATH_VAR) {
            Ok(track_file_path) => {
                Some(File::create(track_file_path).unwrap())
            }
            Err(_e) => { None }
        };

        Self {
            data: LogData::new(),
            track_file,
            order_map: HashMap::new(),
        }
    }

    fn save_internal(&mut self, msg: LogMsg) {
        if let Some(ref mut track_file) = self.track_file {
            serialize_into(&mut *track_file, &msg).expect("Failed to serialize data to stream");
            track_file.flush().expect("Failed to flush stream");
        }
    }


    fn save_tag(&mut self, lb: u32) {
        if lb > 0 {
            let tag = tag_set_wrap::tag_set_find(lb as usize);
            if !self.data.tags.contains_key(&lb) {
                let tagclone = tag.clone();
                self.data.tags.insert(lb, tag);
                self.save_internal(LogMsg::Tag { lb, tag: tagclone });
            }
        }
    }

    pub fn save_magic_bytes(&mut self, bytes: (Vec<u8>, Vec<u8>)) {
        let i = self.data.cond_list.len();
        if i > 0 {
            let bytesclone = bytes.clone();
            self.data.magic_bytes.insert(i - 1, bytes);
            self.save_internal(LogMsg::MagicBytes { i, bytes: bytesclone });
        }
    }

    // like the fn in fparser.rs
    pub fn update_order(&mut self, cond: &mut CondStmtBase) {
        let order_key = (cond.cmpid, cond.context);
        let order = self.order_map.entry(order_key).or_insert(0);
        if cond.order == 0 {
            // first case in switch
            let order_inc = *order + 1;
            *order = order_inc;
        }
        cond.order += *order;
    }

    pub fn save(&mut self, mut cond: CondStmtBase) {
        if cond.lb1 == 0 && cond.lb2 == 0 {
            return;
        }

        if cond.op < defs::COND_AFL_OP || cond.op == defs::COND_FN_OP {
            // !! NOTE: modifies cond.order in place !!
            // returned order is value by which cond.order was *incremented*,
            // i.e. old_order = cond.order - order
            self.update_order(&mut cond);
        }

        // also modify cond to remove len_label information
        // !! NOTE: this will reduce cond.lb1 and cond.lb2 to their normal-label parts !!
        let len_cond = len_label::get_len_cond(&mut cond);

        if (cond.order & 0xffff) <= config::MAX_COND_ORDER {
            self.save_tag(cond.lb1);
            self.save_tag(cond.lb2);

            self.data.cond_list.push(cond);
            self.save_internal(LogMsg::Cond { cond });

            if let Some(mut c) = len_cond {
                c.order += 0x1000000; // avoid the same as cond;

                self.data.cond_list.push(c);
                self.save_internal(LogMsg::Cond { cond: c });
            }
        }
    }

    pub fn save_load(&mut self, path: CString) {
        if self.data.load_paths.insert(path.clone()) {
            self.save_internal(LogMsg::Load { path: path });
        }
    }

    pub fn as_raw_fd(&self) -> Option<c_int> {
        if let Some(ref track_file) = self.track_file {
            Some(track_file.as_raw_fd())
        } else {
            None
        }
    }

    pub fn flush(&mut self) {
        if let Some(ref mut track_file) = self.track_file {
            track_file.flush().expect("failed to flush stream");
        }
    }
}
