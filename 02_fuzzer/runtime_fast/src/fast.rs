use super::{shm_conds, forkcli, shm_branches};
use std::ops::DerefMut;

use std::sync::Once;
use std::os::raw::c_int;

use libc::*;
use std::ffi::CStr;

pub use runtime_common::runtime_hooks::*;

static START: Once = Once::new();

#[ctor]
fn fast_init() {
    START.call_once(|| {
        shm_branches::map_branch_counting_shm();
        forkcli::start_forkcli();
    });
}


#[no_mangle]
pub extern "C" fn __angora_trace_cmp(
    condition: u32,
    cmpid: u32,
    context: u32,
    arg1: u64,
    arg2: u64,
) -> u32 {
    let mut conds = shm_conds::SHM_CONDS.lock().expect("SHM mutex poisoned.");
    match conds.deref_mut() {
        &mut Some(ref mut c) => {
            if c.check_match(cmpid, context) {
                return c.update_cmp(condition, arg1, arg2);
            }
        }
        _ => {}
    }
    condition
}

#[no_mangle]
pub extern "C" fn __angora_trace_switch(cmpid: u32, context: u32, condition: u64) -> u64 {
    let mut conds = shm_conds::SHM_CONDS.lock().expect("SHM mutex poisoned.");
    match conds.deref_mut() {
        &mut Some(ref mut c) => {
            if c.check_match(cmpid, context) {
                return c.update_switch(condition);
            }
        }
        _ => {}
    }
    condition
}

#[no_mangle]
pub unsafe extern "C" fn __angora_dlopen(filename: *const c_char, flag: c_int) -> *mut c_void {
    let mut filename_modified: Vec<u8> = Vec::new();
    filename_modified.extend_from_slice(CStr::from_ptr(filename).to_bytes());
    filename_modified.extend(b".fast\0");
    let mut lib = dlopen(CStr::from_bytes_with_nul_unchecked(&filename_modified).as_ptr(), flag);
    if lib.is_null() {
        lib = dlopen(filename, flag);
    }
    lib
}

#[no_mangle]
pub unsafe extern "C" fn __angora_dlmopen(lmid: Lmid_t, filename: *const c_char, flag: c_int) -> *mut c_void {
    let mut filename_modified: Vec<u8> = Vec::new();
    filename_modified.extend_from_slice(CStr::from_ptr(filename).to_bytes());
    filename_modified.extend(b".fast\0");
    let mut lib = dlmopen(lmid, CStr::from_bytes_with_nul_unchecked(&filename_modified).as_ptr(), flag);
    if lib.is_null() {
        lib = dlmopen(lmid, filename, flag);
    }
    lib
}

#[no_mangle]
pub unsafe extern "C" fn __angora_dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void {
    dlsym(handle, symbol)
}

#[no_mangle]
pub unsafe extern "C" fn __angora_dlvsym(handle: *mut c_void, symbol: *const c_char, _version: *const c_char) -> *mut c_void {
    //TODO: libc crate does not contain dlvsym -> version is currently ignored
    dlsym(handle, symbol)
}