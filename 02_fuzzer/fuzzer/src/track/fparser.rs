use super::filter;
use crate::{
    cond_stmt::{CondState, CondStmt},
    mut_input,
};
use angora_common::{defs, tag::TagSeg};
use std::{collections::HashMap, io, path::Path, fs};
use angora_common::log_data::{LogData, LogMsg};
use bincode::deserialize_from;
use std::collections::HashSet;
use std::ffi::CString;

pub fn get_log_data(path: &Path) -> io::Result<LogData> {
    let f = fs::File::open(path)?;
    if f.metadata().unwrap().len() == 0 {
        return Err(io::Error::new(io::ErrorKind::Other, "Could not find any interesting constraint!, Please make sure taint tracking works or running program correctly."));
    }
    let mut reader = io::BufReader::new(f);
    let mut data = LogData::new();

    loop {
        let msg: bincode::Result<LogMsg> = deserialize_from(&mut reader);
        match msg {
            Ok(msg) => {
                match msg {
                    LogMsg::Tag { lb, tag } => {
                        debug!("Rcv'd tag {:?}", lb);
                        data.tags.insert(lb, tag);
                    }
                    LogMsg::MagicBytes { i, bytes } => {
                        debug!("Rcv'd MagicBytes {:?}", bytes);
                        data.magic_bytes.insert(i - 1, bytes);
                    }
                    LogMsg::Cond { cond } => {
                        debug!("Rcv'd cond {:?}", cond);
                        data.cond_list.push(cond);
                    }
                    LogMsg::Load { path } => {
                        debug!("Rcv'd load {:?}", path);
                        data.load_paths.insert(path);
                    }
                }
            }
            Err(_) => {
                break;
            }
        }
    }
    Ok(data)
}

pub fn read_and_parse(
    out_f: &Path,
    enable_exploitation: bool,
) -> io::Result<(Vec<CondStmt>, HashSet<CString>)> {
    let log_data = get_log_data(out_f)?;

    let mut cond_list: Vec<CondStmt> = Vec::new();
    // assign taint labels and magic_bytes to cond list
    for (i, cond_base) in log_data.cond_list.iter().enumerate() {
        if !enable_exploitation {
            if cond_base.is_exploitable() {
                continue;
            }
        }
        let mut cond = CondStmt::from(*cond_base);
        if cond_base.op != defs::COND_LEN_OP && (cond_base.lb1 > 0 || cond_base.lb2 > 0) {
            if cond_base.size == 0 {
                debug!("cond: {:?}", cond_base);
            }
            get_offsets_and_variables(&log_data.tags, &mut cond, &log_data.magic_bytes.get(&i));
        }

        cond_list.push(cond);
    }
    Ok((cond_list, log_data.load_paths))
}

fn get_offsets_and_variables(
    m: &HashMap<u32, Vec<TagSeg>>,
    cond: &mut CondStmt,
    magic_bytes: &Option<&(Vec<u8>, Vec<u8>)>,
) {
    let empty_offsets: Vec<TagSeg> = vec![];
    let offsets1 = m.get(&cond.base.lb1).unwrap_or(&empty_offsets);
    let offsets2 = m.get(&cond.base.lb2).unwrap_or(&empty_offsets);
    if offsets2.len() == 0 || (offsets1.len() > 0 && offsets1.len() <= offsets2.len()) {
        cond.offsets = offsets1.clone();
        if cond.base.lb2 > 0 && cond.base.lb1 != cond.base.lb2 {
            cond.offsets_opt = offsets2.clone();
        }
        cond.variables = if let Some(args) = magic_bytes {
            [&args.1[..], &args.0[..]].concat()
        } else {
            // if it is integer comparison, we use the bytes of constant as magic bytes.
            mut_input::write_as_ule(cond.base.arg2, cond.base.size as usize)
        };
    } else {
        cond.offsets = offsets2.clone();
        if cond.base.lb1 > 0 && cond.base.lb1 != cond.base.lb2 {
            cond.offsets_opt = offsets1.clone();
        }
        cond.variables = if let Some(args) = magic_bytes {
            [&args.0[..], &args.1[..]].concat()
        } else {
            mut_input::write_as_ule(cond.base.arg1, cond.base.size as usize)
        };
    }
}

pub fn load_track_data(
    out_f: &Path,
    id: u32,
    speed: u32,
    enable_exploitation: bool,
) -> (Vec<CondStmt>, HashSet<CString>) {
    let (mut cond_list, load_paths) = match read_and_parse(out_f, enable_exploitation) {
        Result::Ok(val) => val,
        Result::Err(err) => {
            error!("parse track file error!! {:?}", err);
            (vec![], HashSet::new())
        }
    };

    for cond in cond_list.iter_mut() {
        cond.base.belong = id;
        cond.speed = speed;
        if cond.offsets.len() == 1 && cond.offsets[0].end - cond.offsets[0].begin == 1 {
            cond.state = CondState::OneByte;
        }
    }

    filter::filter_cond_list(&mut cond_list);

    (cond_list, load_paths)
}
