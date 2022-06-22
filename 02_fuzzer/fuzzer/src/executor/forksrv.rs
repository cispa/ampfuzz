use super::{limit::SetLimit, *};
use angora_common::defs::*;
use byteorder::{LittleEndian, ReadBytesExt};
use libc;
use std::{
    collections::HashMap,
    fs,
    io::prelude::*,
    os::unix::{
        io::RawFd,
        net::{UnixListener, UnixStream},
    },
    path::Path,
    process::{Command, Stdio},
    time::Duration,
};
use angora_common::listen_semaphore::ShmListenSemaphore;
use std::net::UdpSocket;

// Just meaningless value for forking a new child
static FORKSRV_NEW_CHILD: [u8; 4] = [8, 8, 8, 8];

#[derive(Debug)]
pub struct Forksrv {
    path: String,
    pub socket: UnixStream,
    uses_asan: bool,
    is_stdin: bool,
    target_addr: String,
    pub time_limit: Option<Duration>
}

impl Forksrv {
    pub fn new(
        socket_path: &str,
        target: &(String, Vec<String>),
        envs: &HashMap<String, String>,
        fd: RawFd,
        is_stdin: bool,
        uses_asan: bool,
        response_time_limit: u64,
        mem_limit: u64,
        target_addr: &str,
    ) -> Forksrv {
        debug!("socket_path: {:?}", socket_path);
        let listener = match UnixListener::bind(socket_path) {
            Ok(sock) => sock,
            Err(e) => {
                error!("FATAL: Failed to bind to socket: {:?}", e);
                panic!();
            }
        };

        let mut envs_fk = envs.clone();
        envs_fk.insert(ENABLE_FORKSRV.to_string(), String::from("TRUE")); // <- TODO: Useless?
        envs_fk.insert(FORKSRV_SOCKET_PATH_VAR.to_string(), socket_path.to_owned());
        match Command::new(&target.0)
            .args(&target.1)
            .stdin(Stdio::null())
            .envs(&envs_fk)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .mem_limit(mem_limit.clone())
            .setsid()
            .pipe_stdin(fd, is_stdin)
            .spawn()
        {
            Ok(_) => (),
            Err(e) => {
                error!("FATAL: Failed to spawn child. Reason: {}", e);
                panic!();
            }
        };

        // FIXME: block here if client doesn't exist.
        let (socket, _) = match listener.accept() {
            Ok(a) => a,
            Err(e) => {
                error!("FATAL: failed to accept from socket: {:?}", e);
                panic!();
            }
        };

        socket
            .set_read_timeout(Some(Duration::from_micros(response_time_limit)))
            .expect("Couldn't set read timeout");
        socket
            .set_write_timeout(Some(Duration::from_micros(response_time_limit)))
            .expect("Couldn't set write timeout");

        debug!("All right -- Init ForkServer {} successfully!", socket_path);

        Forksrv {
            path: socket_path.to_owned(),
            socket,
            uses_asan,
            is_stdin,
            target_addr: target_addr.to_owned(),
            time_limit: Some(Duration::from_micros(response_time_limit)),
        }
    }

    pub fn run(&mut self, listen_sem: &ShmListenSemaphore, input: &Vec<u8>) -> StatusType {
        if self.socket.write(&FORKSRV_NEW_CHILD).is_err() {
            warn!("Fail to write socket!!");
            return StatusType::Error;
        }

        let mut buf = vec![0; 4];
        let child_pid: i32;
        match self.socket.read(&mut buf) {
            Ok(_) => {
                child_pid = match (&buf[..]).read_i32::<LittleEndian>() {
                    Ok(a) => a,
                    Err(e) => {
                        warn!("Unable to recover child pid: {:?}", e);
                        return StatusType::Error;
                    }
                };
                if child_pid <= 0 {
                    warn!(
                        "Unable to request new process from frok server! {}",
                        child_pid
                    );
                    return StatusType::Error;
                }
            }
            Err(error) => {
                warn!("Fail to read child_id -- {}", error);
                return StatusType::Error;
            }
        }

        //TODO AMP_FUZZ:
        // 1. wait for semaphore
        listen_sem.wait();
        // 2. send packet(s)
        let socket = UdpSocket::bind("0.0.0.0:0").expect("failed to bind fuzzer socket");
        socket.send_to(input, &self.target_addr).expect("failed to send input to target");
        // 3. listen for output
        socket.set_read_timeout(self.time_limit).expect("failed to set socket timeout");
        let mut output = [0; 8192];
        let _output_len = socket.recv(&mut output);
        //TODO: forksrv-support for ampfuzz not implemented yet

        buf = vec![0; 4];

        let read_result = self.socket.read(&mut buf);

        match read_result {
            Ok(_) => {
                let status = match (&buf[..]).read_i32::<LittleEndian>() {
                    Ok(a) => a,
                    Err(e) => {
                        warn!("Unable to recover result from child: {}", e);
                        return StatusType::Error;
                    }
                };
                let exit_code = libc::WEXITSTATUS(status);
                let signaled = libc::WIFSIGNALED(status);
                if signaled || (self.uses_asan && exit_code == MSAN_ERROR_CODE) {
                    debug!("Crash code: {}", status);
                    StatusType::Crash
                } else {
                    StatusType::Normal
                }
            }

            Err(_) => {
                unsafe {
                    libc::kill(child_pid, libc::SIGKILL);
                }
                let tmout_buf = &mut [0u8; 16];
                while let Err(_) = self.socket.read(tmout_buf) {
                    warn!("Killing timed out process");
                }
                return StatusType::Normal;//Timeout;
            }
        }
    }
}

impl Drop for Forksrv {
    fn drop(&mut self) {
        debug!("Exit Forksrv");
        // Tell the child process to exit
        let fin = [0u8; 2];
        if self.socket.write(&fin).is_err() {
            debug!("Fail to write socket !!  FIN ");
        }
        let path = Path::new(&self.path);
        if path.exists() {
            if fs::remove_file(&self.path).is_err() {
                warn!("Fail to remove socket file!!  FIN ");
            }
        }
    }
}
