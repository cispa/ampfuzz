use super::*;
use crate::tag_set_wrap;
use crate::logger::Logger;
use angora_common::{cond_stmt_base::*, defs};
use lazy_static::lazy_static;
use libc::*;
use std::{slice, sync::Mutex};

pub use runtime_common::runtime_hooks::*;
use std::os::raw::c_int;
use std::ffi::CStr;

// use shm_conds;
lazy_static! {
    static ref LC: Mutex<Option<Logger>> = Mutex::new(Some(Logger::new()));
    static ref REAL_CLOSE:fn (fd: c_int) -> c_int = unsafe { std::mem::transmute(dlsym_next("close")) };
}

// initialize in ctor
#[ctor]
fn track_init() {
    lazy_static::initialize(&LC);
}

fn infer_eq_sign(op: u32, lb1: u32, lb2: u32) -> u32 {
    if op == defs::COND_ICMP_EQ_OP
        && ((lb1 > 0 && tag_set_wrap::tag_set_get_sign(lb1 as usize))
        || (lb2 > 0 && tag_set_wrap::tag_set_get_sign(lb2 as usize)))
    {
        return op | defs::COND_SIGN_MASK;
    }
    op
}

fn infer_shape(lb: u32, size: u32) {
    if lb > 0 {
        tag_set_wrap::__angora_tag_set_infer_shape_in_math_op(lb, size);
    }
}

fn gettid() -> pid_t {
    return unsafe { libc::syscall(libc::SYS_gettid) } as pid_t;
}

#[no_mangle]
pub extern "C" fn __angora_trace_cmp_tt(
    _cmpid: u32,
    _context: u32,
    _last_callsite: u32,
    _size: u32,
    _op: u32,
    _arg1: u64,
    _arg2: u64,
    _condition: u32,
) {
    panic!("Forbid calling __angora_trace_cmp_tt directly");
}

#[no_mangle]
pub extern "C" fn __dfsw___angora_trace_cmp_tt(
    cmpid: u32,
    context: u32,
    last_callsite: u32,
    size: u32,
    op: u32,
    arg1: u64,
    arg2: u64,
    condition: u32,
    _lcmpid: DfsanLabel,
    _lcontext: DfsanLabel,
    _lcallsite: DfsanLabel,
    _lsize: DfsanLabel,
    _lop: DfsanLabel,
    larg1: DfsanLabel,
    larg2: DfsanLabel,
    _lcondition: DfsanLabel,
) {
    //println!("[CMP] id: {}, ctx: {}", cmpid, get_context());
    // ret_label: *mut DfsanLabel
    let lb1 = larg1;
    let lb2 = larg2;
    if lb1 == 0 && lb2 == 0 {
        return;
    }

    let op = infer_eq_sign(op, lb1, lb2);
    infer_shape(lb1, size);
    infer_shape(lb2, size);

    log_cmp_callsite(cmpid, context, last_callsite, condition, op, size, lb1, lb2, arg1, arg2);
}

#[no_mangle]
pub extern "C" fn __angora_trace_switch_tt(
    _a: u32,
    _b: u32,
    _last_callsite: u32,
    _c: u32,
    _d: u64,
    _e: u32,
    _f: *mut u64,
) {
    panic!("Forbid calling __angora_trace_switch_tt directly");
}


#[no_mangle]
pub extern "C" fn __dfsw___angora_trace_switch_tt(
    cmpid: u32,
    context: u32,
    last_callsite: u32,
    size: u32,
    condition: u64,
    num: u32,
    args: *mut u64,
    _l0: DfsanLabel,
    _l1: DfsanLabel,
    _lcallsite: DfsanLabel,
    _l2: DfsanLabel,
    l3: DfsanLabel,
    _l3: DfsanLabel,
    _l4: DfsanLabel,
) {
    let lb = l3;
    if lb == 0 {
        return;
    }

    infer_shape(lb, size);

    let mut op = defs::COND_SW_OP;
    if tag_set_wrap::tag_set_get_sign(lb as usize) {
        op |= defs::COND_SIGN_MASK;
    }

    let cond = CondStmtBase {
        cmpid,
        thread_id: gettid(),
        context,
        last_callsite,
        order: 0,
        belong: 0,
        condition: defs::COND_FALSE_ST,
        level: 0,
        op,
        size,
        lb1: lb,
        lb2: 0,
        arg1: condition,
        arg2: 0,
    };

    let sw_args = unsafe { slice::from_raw_parts(args, num as usize) };

    let mut lcl = LC.lock().expect("Could not lock LC.");
    if let Some(ref mut lc) = *lcl {
        for (i, arg) in sw_args.iter().enumerate() {
            let mut cond_i = cond.clone();
            cond_i.order += (i << 16) as u32;
            cond_i.arg2 = *arg;
            if *arg == condition {
                cond_i.condition = defs::COND_DONE_ST;
            }
            lc.save(cond_i);
        }
    }
}

#[no_mangle]
pub extern "C" fn __angora_trace_fn_tt(
    _a: u32,
    _b: u32,
    _last_callsite: u32,
    _c: u32,
    _d: *mut i8,
    _e: *mut i8,
) {
    panic!("Forbid calling __angora_trace_fn_tt directly");
}

#[no_mangle]
pub extern "C" fn __dfsw___angora_trace_fn_tt(
    cmpid: u32,
    context: u32,
    last_callsite: u32,
    size: u32,
    parg1: *mut i8,
    parg2: *mut i8,
    _l0: DfsanLabel,
    _l1: DfsanLabel,
    _lcallsite: DfsanLabel,
    _l2: DfsanLabel,
    _l3: DfsanLabel,
    _l4: DfsanLabel,
) {
    let (arglen1, arglen2) = if size == 0 {
        unsafe { (libc::strlen(parg1) as usize, libc::strlen(parg2) as usize) }
    } else {
        (size as usize, size as usize)
    };

    let lb1 = unsafe { dfsan_read_label(parg1, arglen1) };
    let lb2 = unsafe { dfsan_read_label(parg2, arglen2) };

    println!("lb1: {}, lb2: {}", lb1, lb2);
    if lb1 == 0 && lb2 == 0 {
        return;
    }

    let arg1 = unsafe { slice::from_raw_parts(parg1 as *mut u8, arglen1) }.to_vec();
    let arg2 = unsafe { slice::from_raw_parts(parg2 as *mut u8, arglen2) }.to_vec();

    let mut cond = CondStmtBase {
        cmpid,
        thread_id: gettid(),
        context,
        last_callsite,
        order: 0,
        belong: 0,
        condition: defs::COND_FALSE_ST,
        level: 0,
        op: defs::COND_FN_OP,
        size: 0,
        lb1: 0,
        lb2: 0,
        arg1: 0,
        arg2: 0,
    };

    if lb1 > 0 {
        cond.lb1 = lb1;
        cond.size = arglen2 as u32;
    } else if lb2 > 0 {
        cond.lb2 = lb2;
        cond.size = arglen1 as u32;
    }
    let mut lcl = LC.lock().expect("Could not lock LC.");
    if let Some(ref mut lc) = *lcl {
        lc.save(cond);
        lc.save_magic_bytes((arg1, arg2));
    }
}

#[no_mangle]
pub extern "C" fn __angora_trace_exploit_val_tt(
    _a: u32,
    _b: u32,
    _last_callsite: u32,
    _c: u32,
    _d: u32,
    _e: u64,
) {
    panic!("Forbid calling __angora_trace_exploit_val_tt directly");
}

#[no_mangle]
pub extern "C" fn __dfsw___angora_trace_exploit_val_tt(
    cmpid: u32,
    context: u32,
    last_callsite: u32,
    size: u32,
    op: u32,
    val: u64,
    _l0: DfsanLabel,
    _l1: DfsanLabel,
    _lcallsite: DfsanLabel,
    _l2: DfsanLabel,
    _l3: DfsanLabel,
    l4: DfsanLabel,
) {
    let lb: DfsanLabel = l4;
    if len_label::is_len_label(lb) || lb == 0 {
        return;
    }

    log_cmp_callsite(cmpid, context, last_callsite, defs::COND_FALSE_ST, op, size, lb, 0, val, 0);
}


#[allow(dead_code)]
#[inline]
fn log_cmp(
    cmpid: u32,
    context: u32,
    condition: u32,
    op: u32,
    size: u32,
    lb1: u32,
    lb2: u32,
    arg1: u64,
    arg2: u64,
) {
    log_cmp_callsite(cmpid, context, 0, condition, op, size, lb1, lb2, arg1, arg2)
}


#[inline]
fn log_cmp_callsite(
    cmpid: u32,
    context: u32,
    last_callsite: u32,
    condition: u32,
    op: u32,
    size: u32,
    lb1: u32,
    lb2: u32,
    arg1: u64,
    arg2: u64,
) {
    let cond = CondStmtBase {
        cmpid,
        thread_id: gettid(),
        context,
        last_callsite,
        order: 0,
        belong: 0,
        condition,
        level: 0,
        op,
        size,
        lb1,
        lb2,
        arg1,
        arg2,
    };
    //println!("[CMP] id: {}, ctx: {}, last_callsite: {}", cmpid, context, last_callsite);
    let mut lcl = LC.lock().expect("Could not lock LC.");
    if let Some(ref mut lc) = *lcl {
        lc.save(cond);
    }
}

#[no_mangle]
pub extern "C" fn __angora_track_fini_rs() {
    let mut lcl = LC.lock().expect("Could not lock LC.");
    if let Some(ref mut lc) = *lcl {
        lc.flush();
    }
}

// prevent closing our track-socket
#[no_mangle]
pub extern "C" fn close(fd: c_int) -> c_int {
    let mut lcl = LC.lock().expect("Could not lock LC.");
    if let Some(ref mut lc) = *lcl {
        if let Some(log_fd) = lc.as_raw_fd() {
            // if we are about to close the logging fd, just lie and pretend it worked
            if fd == log_fd {
                return 0;
            }
        }
    }
    REAL_CLOSE(fd)
}

#[no_mangle]
pub unsafe extern "C" fn __angora_dlopen(filename: *const c_char, flag: c_int) -> *mut c_void {
    let mut filename_modified: Vec<u8> = Vec::new();
    filename_modified.extend_from_slice(CStr::from_ptr(filename).to_bytes());
    filename_modified.extend(b".track\0");
    let mut lib = dlopen(CStr::from_bytes_with_nul_unchecked(&filename_modified).as_ptr(), flag);
    if !lib.is_null() {
        eprintln!("[DLOPEN] [SUCCESS] {:?}", CStr::from_bytes_with_nul_unchecked(&filename_modified));
        let mut lcl = LC.lock().expect("Could not lock LC.");
        if let Some(ref mut lc) = *lcl {
            lc.save_load(CStr::from_ptr(filename).to_owned());
        }
    } else {
        let emsg_ptr = dlerror();
        let emsg = CStr::from_ptr(emsg_ptr);
        eprintln!("[DLOPEN] [FAIL] {:?}, reason: {:?}, falling back to {:?}", CStr::from_bytes_with_nul_unchecked(&filename_modified), emsg, CStr::from_ptr(filename));
        lib = dlopen(filename, flag);
    }
    lib
}

#[no_mangle]
pub unsafe extern "C" fn __angora_dlmopen(lmid: Lmid_t, filename: *const c_char, flag: c_int) -> *mut c_void {
    let mut filename_modified: Vec<u8> = Vec::new();
    filename_modified.extend_from_slice(CStr::from_ptr(filename).to_bytes());
    filename_modified.extend(b".track\0");
    let mut lib = dlmopen(lmid, CStr::from_bytes_with_nul_unchecked(&filename_modified).as_ptr(), flag);
    if !lib.is_null() {
        eprintln!("[DLOPEN] [SUCCESS] {:?}", CStr::from_bytes_with_nul_unchecked(&filename_modified));
        let mut lcl = LC.lock().expect("Could not lock LC.");
        if let Some(ref mut lc) = *lcl {
            lc.save_load(CStr::from_ptr(filename).to_owned());
        }
    } else {
        let emsg_ptr = dlerror();
        let emsg = CStr::from_ptr(emsg_ptr);
        eprintln!("[DLOPEN] [FAIL] {:?}, reason: {:?}, falling back to {:?}", CStr::from_bytes_with_nul_unchecked(&filename_modified), emsg, CStr::from_ptr(filename));
        lib = dlmopen(lmid, filename, flag);
    }
    lib
}

#[no_mangle]
pub unsafe extern "C" fn __angora_dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void {
    let mut symbol_modified: Vec<u8> = Vec::new();
    symbol_modified.extend(b"dfs$");
    symbol_modified.extend_from_slice(CStr::from_ptr(symbol).to_bytes());
    symbol_modified.extend(b"\0");
    let mut sym = dlsym(handle, CStr::from_bytes_with_nul_unchecked(&symbol_modified).as_ptr());
    if sym.is_null() {
        sym = dlsym(handle, symbol);
    }
    sym
}

#[no_mangle]
pub unsafe extern "C" fn __angora_dlvsym(handle: *mut c_void, symbol: *const c_char, _version: *const c_char) -> *mut c_void {
    //TODO: libc crate does not contain dlvsym -> version is currently ignored
    let mut symbol_modified: Vec<u8> = Vec::new();
    symbol_modified.extend(b"dfs$");
    symbol_modified.extend_from_slice(CStr::from_ptr(symbol).to_bytes());
    symbol_modified.extend(b"\0");
    let mut sym = dlsym(handle, CStr::from_bytes_with_nul_unchecked(&symbol_modified).as_ptr());
    if sym.is_null() {
        sym = dlsym(handle, symbol);
    }
    sym
}