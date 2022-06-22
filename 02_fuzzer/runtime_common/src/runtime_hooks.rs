use std::{env, slice};
use std::ffi::CString;
use std::sync::Mutex;
use std::collections::HashSet;
use std::ops::Deref;
use std::str::FromStr;

use libc::*;

use crate::shm_listen_semaphore;
use angora_common::defs::{FUZZ_PORT_VAR, EARLY_TERMINATION_VAR, EarlyTermination};
use std::cmp::min;


pub unsafe fn dlsym_next(symbol: &str) -> *const u8 {
    let symbol_cstr = CString::new(symbol).expect("CString::new failed");
    let ptr = dlsym(RTLD_NEXT, symbol_cstr.as_ptr());
    if ptr.is_null() {
        panic!("Unable to find underlying function for {}", symbol);
    }
    ptr as *const u8
}

lazy_static! {
    static ref REAL_BIND: fn (sockfd: c_int, addr: *const sockaddr, addrlen: socklen_t) -> c_int = unsafe{ std::mem::transmute(dlsym_next("bind")) };
    static ref REAL_SOCKET:fn (domain: c_int, ty: c_int,  protocol: c_int) -> c_int = unsafe{ std::mem::transmute(dlsym_next("socket")) };
    static ref REAL_RECV:fn (socket: c_int, buf: *mut c_void, len: size_t, flags: c_int) -> ssize_t = unsafe{ std::mem::transmute(dlsym_next("recv")) };
    static ref REAL_RECVFROM:fn (socket: c_int, buf: *mut c_void, len: size_t, flags: c_int, addr: *mut sockaddr, addrlen: *mut socklen_t) -> ssize_t = unsafe{ std::mem::transmute(dlsym_next("recvfrom")) };
    static ref REAL_RECVMSG:fn (fd: c_int, msg: *mut msghdr, flags: c_int) -> ssize_t = unsafe{ std::mem::transmute(dlsym_next("recvmsg")) };
    static ref REAL_RECVMMSG:fn (sockfd: c_int, msgvec: *mut mmsghdr, vlen: c_uint, flags: c_int, timeout: *mut timespec) -> c_int = unsafe{ std::mem::transmute(dlsym_next("recvmmsg")) };
    static ref REAL_SELECT:fn (nfds: c_int, readfs: *mut fd_set, writefds: *mut fd_set, errorfds: *mut fd_set, timeout: *mut timeval) -> c_int = unsafe { std::mem::transmute(dlsym_next("select")) };
    static ref REAL_PSELECT:fn (nfds: c_int, readfs: *mut fd_set, writefds: *mut fd_set, errorfds: *mut fd_set, timeout: *const timespec, sigmask: *const sigset_t) -> c_int = unsafe { std::mem::transmute(dlsym_next("pselect")) };
    static ref REAL_POLL:fn (fds: *mut pollfd, nfds: nfds_t, timeout: c_int) -> c_int = unsafe { std::mem::transmute(dlsym_next("poll")) };
    static ref REAL_PPOLL:fn (fds: *mut pollfd, nfds: nfds_t, timeout: c_int, sigmask: *const sigset_t) -> c_int = unsafe { std::mem::transmute(dlsym_next("ppoll")) };
    static ref REAL_EPOLL_WAIT:fn (epfd: c_int, events: *mut epoll_event, maxevents: c_int, timeout: c_int) -> c_int = unsafe { std::mem::transmute(dlsym_next("epoll_wait")) };
    static ref REAL_EPOLL_PWAIT:fn (epfd: c_int, events: *mut epoll_event, maxevents: c_int, timeout: c_int, sigmask: *const sigset_t) -> c_int = unsafe { std::mem::transmute(dlsym_next("epoll_pwait")) };
    static ref REAL_EPOLL_CTL:fn (epfd: c_int, op: c_int, fd: c_int, event: *mut epoll_event) -> c_int = unsafe { std::mem::transmute(dlsym_next("epoll_ctl")) };


    static ref FUZZ_PORT: u16 = match env::var(FUZZ_PORT_VAR){
        Ok(val) => {debug!("got a port, parsing..."); val.parse::<u16>().expect("Could not parse port as u16 value.")}
        Err(_) => {debug!("no port given :("); 0}
    };

    static ref EARLY_TERMINATION: EarlyTermination = match env::var(EARLY_TERMINATION_VAR){
        Ok(v) => {EarlyTermination::from_str(&v).unwrap_or(EarlyTermination::Full)}
        Err(_) => {debug!("full early termination enabled"); EarlyTermination::Full}
    };

    static ref UDP_SOCKETS: Mutex<HashSet<u32>> = Mutex::new(HashSet::new());
    static ref FUZZING_FD: Mutex<Option<u32>> = Mutex::new(None);
    static ref HAS_READ: Mutex<bool> = Mutex::new(false);
}

#[link(name = "systemd")]
#[no_mangle]
extern "C" {
    fn sd_is_socket_inet(fd: c_int, family: c_int, sock_type: c_int, listening: c_int, port: c_ushort) -> c_int;
}

#[no_mangle]
pub extern "C" fn is_fuzz_fd(sockfd: c_int) -> bool {
    debug!("sd_is_socket_inet({}, {}, {}, {}, {})", sockfd, AF_INET, SOCK_DGRAM, -1, *FUZZ_PORT);
    let r = unsafe { sd_is_socket_inet(sockfd, AF_INET, SOCK_DGRAM, -1, *FUZZ_PORT) };
    debug!("sd_is_socket_inet returned {}", r);
    r > 0
}

#[no_mangle]
pub extern "C" fn is_blocking_fd(fd: i32) -> bool {
    (unsafe { libc::fcntl(fd, libc::F_GETFL) } & libc::O_NONBLOCK) == 0
}

#[no_mangle]
pub extern "C" fn __angora_listen_ready() -> bool {
    let maybe_semaphore = shm_listen_semaphore::LISTEN_SEM.lock().expect("unable to obtain LISTEN_SEM mutex!");
    match maybe_semaphore.deref() {
        Some(semaphore) => semaphore.post(),
        _ => { true }
    }
}

#[no_mangle]
pub extern "C" fn __angora_check_terminate_static() {
    if *EARLY_TERMINATION == EarlyTermination::Static || *EARLY_TERMINATION == EarlyTermination::Full {
        //eprint!("Should I terminate? ");
        if *(HAS_READ.lock().expect("failed to lock HAS_READ")) {
            debug!("YES!");
            unsafe { pthread_exit(std::ptr::null_mut()) };
        }
        debug!("not yet.");
    } else {
        debug!("Early termination disabled");
    }
}

#[no_mangle]
pub extern "C" fn __angora_check_terminate() {
    if *EARLY_TERMINATION == EarlyTermination::Dynamic || *EARLY_TERMINATION == EarlyTermination::Full {
        //eprint!("Should I terminate? ");
        if *(HAS_READ.lock().expect("failed to lock HAS_READ")) {
            debug!("YES!");
            unsafe { pthread_exit(std::ptr::null_mut()) };
        }
        debug!("not yet.");
    } else {
        debug!("Early termination disabled");
    }
}

/*
#[no_mangle]
pub unsafe extern "C" fn bind(sockfd: c_int, addr: *const sockaddr, addrlen: socklen_t) -> c_int {
    let ffds = UDP_SOCKETS.lock().expect("failed to lock UDP_SOCKETS");
    if ffds.contains(&(sockfd as u32)) {
        drop(ffds); //release lock
        debug!("About to call bind on a udp socket, checking port and address family!");
        let addr_in = (addr as *const sockaddr_in);
        if (*addr_in).sin_family as c_int == AF_INET && (*addr_in).sin_port == *FUZZ_PORT_BIG_ENDIAN {
            debug!("Binding fuzzing FD!!");
            let mut fuzz_port = FUZZING_FD.lock().expect("failed to lock FUZZING_FD");
            *fuzz_port = Some(sockfd as u32);
        }
    }
    debug!("Calling the real bind");
    let ret = REAL_BIND(sockfd, addr, addrlen);
    debug!("Called the real bind, got {}", ret);
    ret
}
*/

/*
#[no_mangle]
pub unsafe extern "C" fn socket(domain: c_int, ty: c_int, protocol: c_int) -> c_int {
    debug!("Calling the real socket");
    let sock_fd = REAL_SOCKET(domain, ty, protocol);
    debug!("Called the real socket, got {}", sock_fd);
    if ty == SOCK_DGRAM && sock_fd >= 0 {
        debug!("Adding fd {} to set of udp sockets", sock_fd);
        let mut ffds = UDP_SOCKETS.lock().expect("failed to lock UDP_SOCKETS");
        ffds.insert(sock_fd as u32);
    }
    sock_fd
}
*/


#[no_mangle]
pub unsafe extern "C" fn recv(socket: c_int, buf: *mut c_void, len: size_t, flags: c_int) -> ssize_t {
    let is_fuzz_fd = is_fuzz_fd(socket);
    debug!("fd {} is {}a fuzzing fd", socket, if is_fuzz_fd { "" } else { "not " });
    if is_fuzz_fd {
        if is_blocking_fd(socket) { __angora_check_terminate(); }
        __angora_listen_ready();
    }
    let ret = REAL_RECV(socket, buf, len, flags);
    if is_fuzz_fd {
        debug!("recv on fuzzing fd!");
        if ret >= 0 {
            *HAS_READ.lock().expect("failed to lock HAS_READ") = true;
        }
    }
    ret
}

#[no_mangle]
pub unsafe extern "C" fn recvfrom(socket: c_int, buf: *mut c_void, len: size_t, flags: c_int, addr: *mut sockaddr, addrlen: *mut socklen_t) -> ssize_t {
    let is_fuzz_fd = is_fuzz_fd(socket);
    debug!("fd {} is {}a fuzzing fd", socket, if is_fuzz_fd { "" } else { "not " });
    if is_fuzz_fd {
        if is_blocking_fd(socket) { __angora_check_terminate(); }
        __angora_listen_ready();
    }
    let ret = REAL_RECVFROM(socket, buf, len, flags, addr, addrlen);
    if is_fuzz_fd {
        debug!("recvfrom on fuzzing fd!");
        if ret >= 0 {
            *HAS_READ.lock().expect("failed to lock HAS_READ") = true;
        }
    }
    ret
}

#[no_mangle]
pub unsafe extern "C" fn recvmsg(socket: c_int, msg: *mut msghdr, flags: c_int) -> ssize_t {
    let is_fuzz_fd = is_fuzz_fd(socket);
    debug!("fd {} is {}a fuzzing fd", socket, if is_fuzz_fd { "" } else { "not " });
    if is_fuzz_fd {
        if is_blocking_fd(socket) { __angora_check_terminate(); }
        __angora_listen_ready();
    }
    let ret = REAL_RECVMSG(socket, msg, flags);
    if is_fuzz_fd {
        debug!("recvmsg on fuzzing fd!");
        if ret >= 0 {
            *HAS_READ.lock().expect("failed to lock HAS_READ") = true;
        }
    }
    ret
}

#[no_mangle]
pub unsafe extern "C" fn recvmmsg(sockfd: c_int, msgvec: *mut mmsghdr, vlen: c_uint, flags: c_int, timeout: *mut timespec) -> c_int {
    let is_fuzz_fd = is_fuzz_fd(sockfd);
    debug!("fd {} is {}a fuzzing fd", sockfd, if is_fuzz_fd { "" } else { "not " });
    if is_fuzz_fd {
        if is_blocking_fd(sockfd) { __angora_check_terminate(); }
        __angora_listen_ready();
    }
    let ret = REAL_RECVMMSG(sockfd, msgvec, vlen, flags, timeout);
    if is_fuzz_fd {
        debug!("recvmmsg on fuzzing fd!");
        if ret > 0 {
            *HAS_READ.lock().expect("failed to lock HAS_READ") = true;
        }
    }
    ret
}

#[no_mangle]
pub unsafe extern "C" fn select(nfds: c_int, readfs: *mut fd_set, writefds: *mut fd_set, errorfds: *mut fd_set, timeout: *mut timeval) -> c_int {
    for i in 0..min(nfds as usize, libc::FD_SETSIZE) as c_int {
        if libc::FD_ISSET(i, readfs) {
            if is_fuzz_fd(i) {
                __angora_check_terminate();
                __angora_listen_ready();
                break;
            }
        }
    }
    REAL_SELECT(nfds, readfs, writefds, errorfds, timeout)
}

#[no_mangle]
pub unsafe extern "C" fn pselect(nfds: c_int, readfs: *mut fd_set, writefds: *mut fd_set, errorfds: *mut fd_set, timeout: *const timespec, sigmask: *const sigset_t) -> c_int {
    for i in 0..min(nfds as usize, libc::FD_SETSIZE) as c_int {
        if libc::FD_ISSET(i, readfs) {
            if is_fuzz_fd(i) {
                __angora_check_terminate();
                __angora_listen_ready();
                break;
            }
        }
    }
    REAL_PSELECT(nfds, readfs, writefds, errorfds, timeout, sigmask)
}

#[no_mangle]
pub unsafe extern "C" fn poll(fds: *mut pollfd, nfds: nfds_t, timeout: c_int) -> c_int {
    let fdslice = slice::from_raw_parts(fds, nfds as usize);
    for i in 0..nfds as usize {
        if is_fuzz_fd(fdslice[i].fd) && (fdslice[i].events & (POLLIN | POLLRDNORM | POLLRDBAND | POLLPRI)) != 0 {
            __angora_check_terminate();
            __angora_listen_ready();
            break;
        }
    }
    REAL_POLL(fds, nfds, timeout)
}

#[no_mangle]
pub unsafe extern "C" fn ppoll(fds: *mut pollfd, nfds: nfds_t, timeout: c_int, sigmask: *const sigset_t) -> c_int {
    let fdslice = slice::from_raw_parts(fds, nfds as usize);
    for i in 0..nfds as usize {
        if is_fuzz_fd(fdslice[i].fd) && (fdslice[i].events & (POLLIN | POLLRDNORM | POLLRDBAND | POLLPRI)) != 0 {
            __angora_check_terminate();
            __angora_listen_ready();
            break;
        }
    }
    REAL_PPOLL(fds, nfds, timeout, sigmask)
}

#[no_mangle]
pub unsafe extern "C" fn epoll_wait(epfd: c_int, events: *mut epoll_event, maxevents: c_int, timeout: c_int) -> c_int {
    __angora_check_terminate();
    REAL_EPOLL_WAIT(epfd, events, maxevents, timeout)
}

#[no_mangle]
pub unsafe extern "C" fn epoll_pwait(epfd: c_int, events: *mut epoll_event, maxevents: c_int, timeout: c_int, sigmask: *const sigset_t) -> c_int {
    __angora_check_terminate();
    REAL_EPOLL_PWAIT(epfd, events, maxevents, timeout, sigmask)
}

#[no_mangle]
pub unsafe extern "C" fn epoll_ctl(epfd: c_int, op: c_int, fd: c_int, event: *mut epoll_event) -> c_int {
    if (op == EPOLL_CTL_ADD || op == EPOLL_CTL_MOD) && is_fuzz_fd(fd) {
        __angora_listen_ready();
    }
    REAL_EPOLL_CTL(epfd, op, fd, event)
}

#[no_mangle]
pub unsafe extern "C" fn fork() -> pid_t {
    // Hacky work-around in dealing with fork.
    // Instead of forking a child, just assume the child is the interesting branch
    // and continue executing as the child, but re-use the parent-process
    warn!("encountered fork! Assuming action happens in the child");
    0
}