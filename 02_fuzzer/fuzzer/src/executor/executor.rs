use super::{limit::SetLimit, *};

use crate::{branches, command, cond_stmt::{self, NextState}, depot, stats, dyncfg::cfg::{CmpId}};
use angora_common::{config, defs, tag::TagSeg, listen_semaphore};

use std::{collections::HashMap, path::Path, process::{Command, Stdio}, sync::{
    atomic::{compiler_fence, Ordering},
    Arc, RwLock,
}, time};
use wait_timeout::ChildExt;
use itertools::Itertools;
use std::net::UdpSocket;
use crate::executor::recv_thread::RecvThread;
use crate::cond_stmt::CondStmt;
use crate::byte_count::{UdpByteCount, AmpByteCount};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use crate::track::load_track_data;
use std::thread::sleep;

pub struct Executor {
    pub cmd: command::CommandOpt,
    pub branches: branches::Branches,
    pub t_conds: cond_stmt::ShmConds,
    pub listen_sem: listen_semaphore::ShmListenSemaphore,
    envs: HashMap<String, String>,
    forksrv: Option<Forksrv>,
    depot: Arc<depot::Depot>,
    fd: PipeFd,
    tmout_cnt: usize,
    invariable_cnt: usize,
    pub last_f: u64,
    pub has_new_path: bool,
    pub has_good_amp: bool,
    pub global_stats: Arc<RwLock<stats::ChartStats>>,
    pub local_stats: stats::LocalStats,
    is_directed: bool,
}

impl Executor {
    pub fn new(
        cmd: command::CommandOpt,
        global_branches: Arc<branches::GlobalBranches>,
        depot: Arc<depot::Depot>,
        global_stats: Arc<RwLock<stats::ChartStats>>,
    ) -> Self {
        // ** Share Memory **
        let branches = branches::Branches::new(global_branches);
        let t_conds = cond_stmt::ShmConds::new();
        let listen_sem = listen_semaphore::ShmListenSemaphore::new();

        // ** Envs **
        let mut envs = HashMap::new();
        envs.insert(
            defs::ASAN_OPTIONS_VAR.to_string(),
            defs::ASAN_OPTIONS_CONTENT.to_string(),
        );
        envs.insert(
            defs::MSAN_OPTIONS_VAR.to_string(),
            defs::MSAN_OPTIONS_CONTENT.to_string(),
        );
        envs.insert(
            defs::BRANCHES_SHM_ENV_VAR.to_string(),
            branches.get_id().to_string(),
        );
        envs.insert(
            defs::COND_STMT_ENV_VAR.to_string(),
            t_conds.get_id().to_string(),
        );
        if cmd.enable_listen_ready {
            envs.insert(
                defs::LISTEN_SEM_ENV_VAR.to_string(),
                listen_sem.get_id().to_string(),
            );
        }
        envs.insert(
            defs::LD_LIBRARY_PATH_VAR.to_string(),
            cmd.ld_library.clone(),
        );
        /*let target_addr: SocketAddr = cmd.target_addr.parse().expect("Failed to parse target address");
        envs.insert(
            defs::FUZZ_PORT_VAR.to_string(),
            target_addr.port().to_string().clone(),
        );*/

        envs.insert(
            defs::EARLY_TERMINATION_VAR.to_string(),
            cmd.early_termination.to_string(),
        );

        let fd = pipe_fd::PipeFd::new(&cmd.out_file);
        let forksrv = None; //temporarily disable forkserver
        /*Some(forksrv::Forksrv::new(
            &cmd.forksrv_socket_path,
            &cmd.main,
            &envs,
            fd.as_raw_fd(),
            cmd.is_stdin,
            cmd.uses_asan,
            cmd.time_limit,
            cmd.mem_limit,
            &cmd.target_addr,
        ));*/

        let is_directed = cmd.directed_only;

        Self {
            cmd,
            branches,
            t_conds,
            listen_sem,
            envs,
            forksrv,
            depot,
            fd,
            tmout_cnt: 0,
            invariable_cnt: 0,
            last_f: defs::UNREACHABLE,
            has_new_path: false,
            has_good_amp: false,
            global_stats,
            local_stats: Default::default(),
            is_directed,
        }
    }

    pub fn set_directed(&mut self, b: bool) {
        self.is_directed = b;
    }

    pub fn rebind_forksrv(&mut self) {
        {
            // delete the old forksrv
            self.forksrv = None;
        }
        let fs = forksrv::Forksrv::new(
            &self.cmd.forksrv_socket_path,
            &self.cmd.main,
            &self.envs,
            self.fd.as_raw_fd(),
            self.cmd.is_stdin,
            self.cmd.uses_asan,
            self.cmd.response_time_limit,
            self.cmd.mem_limit,
            &self.cmd.target_addr,
        );
        self.forksrv = Some(fs);
    }

    fn check_consistent(&self, output: u64, cond: &mut cond_stmt::CondStmt) {
        if output == defs::UNREACHABLE
            && cond.is_first_time()
            && self.local_stats.num_exec_round == 1.into()
            && cond.state.is_initial()
        {
            cond.is_consistent = false;
            warn!("inconsistent : {:?}", cond);
        }
    }

    fn check_invariable(&mut self, output: u64, cond: &mut cond_stmt::CondStmt) -> bool {
        let mut skip = false;
        if output == self.last_f {
            self.invariable_cnt += 1;
            if self.invariable_cnt >= config::MAX_INVARIABLE_NUM {
                debug!("output is invariable! f: {}", output);
                if cond.is_desirable {
                    cond.is_desirable = false;
                }
                // deterministic will not skip
                if !cond.state.is_det() && !cond.state.is_one_byte() {
                    skip = true;
                }
            }
        } else {
            self.invariable_cnt = 0;
        }
        self.last_f = output;
        skip
    }

    fn check_explored(
        &self,
        cond: &mut cond_stmt::CondStmt,
        _status: &StatusType,
        output: u64,
        explored: &mut bool,
    ) -> bool {
        let mut skip = false;
        // If crash or timeout, constraints after the point won't be tracked.
        if output == 0 && !cond.is_done()
        //&& status == StatusType::Normal
        {
            debug!("Explored this condition!");
            skip = true;
            *explored = true;
            cond.mark_as_done();
        }
        skip
    }

    pub fn run_with_cond(
        &mut self,
        buf: &Vec<u8>,
        cond: &mut cond_stmt::CondStmt,
    ) -> (StatusType, u64) {
        self.run_init();
        self.t_conds.set(cond);
        let mut status = self.run_inner(buf);

        let output = self.t_conds.get_cond_output();
        let mut explored = false;
        let mut skip = false;
        skip |= self.check_explored(cond, &status, output, &mut explored);
        skip |= self.check_invariable(output, cond);
        self.check_consistent(output, cond);

        self.do_if_has_new(buf, &status, explored, Some(cond));
        status = self.check_timeout(&status, cond);

        if skip {
            status = StatusType::Skip;
        }

        (status, output)
    }

    fn try_unlimited_memory(&mut self, buf: &Vec<u8>, cmpid: u32) -> StatusType {
        self.branches.clear_trace();
        if self.cmd.is_stdin {
            self.fd.rewind();
        }
        compiler_fence(Ordering::SeqCst);
        let unmem_status =
            self.run_target(&self.cmd.main, config::MEM_LIMIT_TRACK, self.cmd.startup_time_limit, self.cmd.response_time_limit, buf);
        compiler_fence(Ordering::SeqCst);

        // find difference
        if !matches!(unmem_status, StatusType::Normal|StatusType::Amp(_,_)) {
            warn!(
                "Behavior changes if we unlimit memory!! status={:?}",
                unmem_status
            );
            // crash or hang
            if self.branches.has_new(&unmem_status, self.is_directed).0 {
                self.depot.save(&unmem_status, &buf, cmpid);
            }
        }
        unmem_status
    }

    fn do_if_has_new(&mut self, buf: &Vec<u8>, status: &StatusType, _explored: bool, parent_cond: Option<&CondStmt>) {
        let cmpid = match parent_cond {
            None => { 0 }
            Some(parent_cond) => { parent_cond.base.cmpid }
        };

        // new edge: one byte in bitmap
        let (has_new_path, _has_new_edge, edge_num, has_good_amp) = self.branches.has_new(status, self.is_directed);
        // TODO: check _has_new_edge return value

        if has_new_path | has_good_amp {
            self.has_new_path = has_new_path;
            self.has_good_amp = has_good_amp;
            self.local_stats.find_new(&status, self.branches.get_path_as_hash());
            let id = self.depot.save(status, &buf, cmpid);

            if let StatusType::Normal | StatusType::Amp(_, _) = status {
                self.local_stats.avg_edge_num.update(edge_num as f32);
                let speed = self.count_time(&buf);
                self.local_stats.avg_exec_time.update(speed as f32);

                let unmem_status = self.try_unlimited_memory(buf, cmpid);

                if matches!(unmem_status, StatusType::Amp(_,_)) && self.cmd.enable_amp {
                    // if parent_cond was *not* an amplification, generate amplification conds for this input
                    if parent_cond == None || parent_cond.unwrap().base.op != defs::COND_AMP_OP {
                        self.depot.add_entries(vec![cond_stmt::CondStmt::get_amp_cond(id)]);
                    }
                }

                if has_new_path && matches!(unmem_status, StatusType::Normal|StatusType::Amp(_,_)) {
                    let cond_stmts = self.track(id, buf, speed);
                    if cond_stmts.len() > 0 {
                        self.depot.add_entries(cond_stmts);
                        if self.cmd.enable_afl {
                            self.depot
                                .add_entries(vec![cond_stmt::CondStmt::get_afl_cond(
                                    id, speed, edge_num,
                                )]);
                        }
                    }
                }
            }
        }
    }

    pub fn run(&mut self, buf: &Vec<u8>, cond: &mut cond_stmt::CondStmt) -> StatusType {
        self.run_init();
        let status = self.run_inner(buf);
        self.do_if_has_new(buf, &status, false, Some(cond));
        self.check_timeout(&status, cond)
    }

    pub fn run_sync(&mut self, buf: &Vec<u8>) {
        self.run_init();
        let status = self.run_inner(buf);
        self.do_if_has_new(buf, &status, false, None);
    }

    fn run_init(&mut self) {
        self.has_new_path = false;
        self.local_stats.num_exec.count();
        self.local_stats.num_exec_round.count();
    }

    fn run_exit(&mut self) {
        self.sync_to_global();
    }

    fn check_timeout(&mut self, status: &StatusType, cond: &mut cond_stmt::CondStmt) -> StatusType {
        let mut ret_status = status.clone();
        if ret_status == StatusType::Error {
            self.rebind_forksrv();
            ret_status = StatusType::Timeout;
        }

        if ret_status == StatusType::Timeout {
            self.tmout_cnt = self.tmout_cnt + 1;
            if self.tmout_cnt >= config::TMOUT_SKIP {
                cond.to_timeout();
                ret_status = StatusType::Skip;
                self.tmout_cnt = 0;
            }
        } else {
            self.tmout_cnt = 0;
        };

        ret_status
    }

    fn run_inner(&mut self, buf: &Vec<u8>) -> StatusType {
        self.write_test(buf);

        self.branches.clear_trace();

        compiler_fence(Ordering::SeqCst);
        let ret_status = if let Some(ref mut fs) = self.forksrv {
            fs.run(&self.listen_sem, &buf)
        } else {
            self.run_target(&self.cmd.main, self.cmd.mem_limit, self.cmd.startup_time_limit, self.cmd.response_time_limit, &buf)
        };
        compiler_fence(Ordering::SeqCst);

        self.run_exit();

        ret_status
    }

    fn count_time(&mut self, buf: &Vec<u8>) -> u32 {
        let t_start = time::Instant::now();
        for _ in 0..3 {
            if self.cmd.is_stdin {
                self.fd.rewind();
            }
            if let Some(ref mut fs) = self.forksrv {
                let status = fs.run(&self.listen_sem, &buf);
                if status == StatusType::Error {
                    self.rebind_forksrv();
                    return defs::SLOW_SPEED;
                }
            } else {
                self.run_target(&self.cmd.main, self.cmd.mem_limit, self.cmd.startup_time_limit, self.cmd.response_time_limit, &buf);
            }
        }
        let used_t = t_start.elapsed();
        let used_us = (used_t.as_secs() as u32 * 1000_000) + used_t.subsec_nanos() / 1_000;
        used_us / 3
    }

    fn track(&mut self, id: usize, buf: &Vec<u8>, speed: u32) -> Vec<cond_stmt::CondStmt> {
        let track_socket_path = format!("{}_{}", self.cmd.track_file_path, id);

        self.envs.insert(
            defs::TRACK_FILE_PATH_VAR.to_string(),
            track_socket_path.clone(),
        );

        let t_now: stats::TimeIns = Default::default();

        self.write_test(buf);

        compiler_fence(Ordering::SeqCst);
        let ret_status = self.run_target(
            &self.cmd.track,
            config::MEM_LIMIT_TRACK,
            self.cmd.startup_time_limit * config::TIME_LIMIT_TRACK_FACTOR,
            self.cmd.response_time_limit * config::TIME_LIMIT_TRACK_FACTOR,
            &buf,
        );
        compiler_fence(Ordering::SeqCst);

        if !matches!(ret_status, StatusType::Normal|StatusType::Amp(_,_)) {
            error!(
                "Crash or hang while tracking! -- {:?},  id: {}",
                ret_status, id
            );
            return vec![];
        }

        let (mut cond_list, load_paths) = load_track_data(Path::new(track_socket_path.as_str()), id as u32, speed, self.cmd.enable_exploitation);

        for load_path in load_paths.iter() {
            let mut cfg_file: Vec<u8> = Vec::new();
            cfg_file.extend_from_slice(load_path.to_bytes());
            cfg_file.extend(b".targets.json");

            let cfg_path = Path::new(OsStr::from_bytes(&cfg_file));
            if cfg_path.exists() {
                let mut dyncfg = self.depot.cfg.write().unwrap();
                dyncfg.append_file(cfg_path);
            } else {
                warn!("CFG file {:?} does not exist, ignoring", cfg_path);
            }
        }

        let mut ind_dominator_offsets: HashMap<CmpId, Vec<TagSeg>> = HashMap::new();
        let mut ind_cond_list = vec![];


        for (_, thread_cond_list) in cond_list.clone().into_iter().into_group_map_by(|c| c.base.thread_id).into_iter()
        {
            for (a, b) in thread_cond_list.clone().into_iter().tuple_windows() {
                if a.base.thread_id != b.base.thread_id {
                    error!("Thread-switch occured between track-calls!!");
                }

                let mut dyncfg = self.depot.cfg.write().unwrap();
                let edge = (a.base.cmpid, b.base.cmpid);
                let _is_new = dyncfg.add_edge(edge);

                // Collect indirect call dominator taint
                if dyncfg.dominates_indirect_call(a.base.cmpid) {
                    let entry = ind_dominator_offsets.entry(a.base.cmpid).or_insert(vec![]);
                    debug!("OFFSET set {} {:?}", a.base.cmpid, a.offsets);
                    *entry = a.offsets;
                }

                debug!("VARIABLES: {:?}", a.variables);
                if b.base.last_callsite != 0 {
                    debug!("ADD Indirect edge {:?}: {}!!", edge, b.base.last_callsite);
                    dyncfg.set_edge_indirect(edge, b.base.last_callsite);
                    let dominators =
                        dyncfg.get_callsite_dominators(b.base.last_callsite);
                    let mut fixed_offsets = vec![];
                    for d in dominators {
                        if let Some(offsets) = ind_dominator_offsets.get(&d) {
                            fixed_offsets.extend(offsets.clone());
                        }
                    }
                    dyncfg.set_magic_bytes(edge, &buf, &fixed_offsets);


                    // Set offsets
                    let mut fixed_cond = b.clone();
                    fixed_cond.offsets.append(&mut fixed_offsets);
                    let var_len = fixed_cond.variables.len();
                    for (i, v) in dyncfg.get_magic_bytes(edge) {
                        if i < var_len - 1 {
                            fixed_cond.variables[i] = v;
                            debug!("FIX VAR {} to '{}'", i, v);
                        }
                    }
                    ind_cond_list.push(fixed_cond);
                }
            }
        }


        for cond in cond_list.iter_mut() {
            let dyncfg = self.depot.cfg.read().unwrap();
            if dyncfg.is_target(cond.base.cmpid) {
                cond.set_target(true);
            }
        }

        // Add fixed conds to result
        cond_list.append(&mut ind_cond_list);

        self.local_stats.track_time += t_now.into();
        cond_list
    }

    pub fn random_input_buf(&self) -> Vec<u8> {
        let id = self.depot.next_random();
        self.depot.get_input_buf(id)
    }

    fn write_test(&mut self, buf: &Vec<u8>) {
        self.fd.write_buf(buf);
        if self.cmd.is_stdin {
            self.fd.rewind();
        }
    }

    fn run_target(
        &self,
        target: &(String, Vec<String>),
        mem_limit: u64,
        startup_time_limit: u64,
        response_time_limit: u64,
        input: &Vec<u8>,
    ) -> StatusType {

        // println!("About to run {} {}", self.envs.iter().map(|p| format!("{}={}", p.0, p.1)).join(" "), target.0);

        //AMP_FUZZ:
        // 0. drain semaphore
        self.listen_sem.drain();
        compiler_fence(Ordering::SeqCst);

        let mut cmd = Command::new(&target.0);
        let mut child = cmd
            .args(&target.1)
            .stdin(Stdio::null())
            .env_clear()
            .envs(&self.envs)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .mem_limit(mem_limit.clone())
            .setsid()
            .pipe_stdin(self.fd.as_raw_fd(), self.cmd.is_stdin)
            .spawn()
            .expect("Could not run target");

        let startup_timeout = time::Duration::from_micros(startup_time_limit);
        let response_timeout = time::Duration::from_micros(response_time_limit);

        //AMP_FUZZ:
        if self.cmd.enable_listen_ready {
            // 1. wait a little for semaphore (if enabled)
            if !self.listen_sem.wait_timeout(&startup_timeout) {
                // if we have no success waiting for the semaphore
                // kill the child and record a timeout
                child.kill().expect("Could not send kill signal to child.");
                child.wait().expect("Error during waiting for child.");
                // below used to be StatusType::Timeout,
                // but we don't care if the target is still running
                return StatusType::Timeout;
            }
        } else {
            sleep(startup_timeout);
        }

        // 2. if we have success, prepare the socket
        let socket = UdpSocket::bind("0.0.0.0:0").expect("failed to bind fuzzer socket");

        // 3. start thread to listen for output
        let recv_thread = RecvThread::new(socket.try_clone().expect("Failed to clone socket"));

        // 4. and send our input
        socket.send_to(input, &self.cmd.target_addr).expect("failed to send input to target");

        let mut ret = match child.wait_timeout(response_timeout).unwrap() {
            Some(status) => {
                if let Some(status_code) = status.code() {
                    if (self.cmd.uses_asan && status_code == defs::MSAN_ERROR_CODE)
                        || (self.cmd.mode.is_pin_mode() && status_code > 128)
                    {
                        StatusType::Crash
                    } else {
                        StatusType::Normal
                    }
                } else {
                    StatusType::Crash
                }
            }
            None => {
                // Timeout
                // child hasn't exited yet
                child.kill().expect("Could not send kill signal to child.");
                child.wait().expect("Error during waiting for child.");
                // below used to be StatusType::Timeout,
                // but we don't care if the target is still running
                StatusType::Normal
            }
        };

        // Check number of received bytes
        let output_len = recv_thread.stop();
        if ret == StatusType::Normal && output_len > 0 {
            ret = StatusType::Amp(self.branches.get_path_as_hash(), AmpByteCount {
                bytes_in: UdpByteCount::from_l7(input.len()),
                bytes_out: output_len,
            });
        }

        ret
    }

    pub fn finish_round(&mut self) {
        self.sync_to_global();
        self.global_stats
            .write()
            .unwrap()
            .finish_round();

        self.t_conds.clear();
        self.tmout_cnt = 0;
        self.invariable_cnt = 0;
        self.last_f = defs::UNREACHABLE;
    }

    pub fn sync_to_global(&mut self) {
        self.global_stats
            .write()
            .unwrap()
            .sync_from_local(&mut self.local_stats);
        self.local_stats.clear();
    }
}
