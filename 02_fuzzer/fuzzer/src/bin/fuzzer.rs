#[macro_use]
extern crate clap;
use clap::{App, Arg};

extern crate angora;
extern crate angora_common;
use angora::fuzz_main;
use angora_common::config::{RESPONSE_TIME_LIMIT, STARTUP_TIME_LIMIT};
use angora_common::defs::EarlyTermination;

fn main() {
    let matches = App::new("angora-fuzzer")
        .version(crate_version!())
        .about("Angora is a mutation-based fuzzer. The main goal of Angora is to increase branch coverage by solving path constraints without symbolic execution.")
        .arg(Arg::with_name("mode")
            .short("m")
            .long("mode")
            .value_name("Mode")
            .help("Which binary instrumentation framework are you using?")
            //.possible_values(&["llvm", "pin"]))
            .possible_values(&["llvm"]))
        .arg(Arg::with_name("input_dir")
            .short("i")
            .long("input")
            .value_name("DIR")
            .help("Sets the directory of input seeds, use \"-\" to restart with existing output directory")
            .takes_value(true)
            .required(true))
        .arg(Arg::with_name("output_dir")
            .short("o")
            .long("output")
            .value_name("DIR")
            .help("Sets the directory of outputs")
            .takes_value(true)
            .required(true))
        .arg(Arg::with_name("track_target")
            .short("t")
            .long("track")
            .value_name("PROM")
            .help("Sets the target (USE_TRACK or USE_PIN) for tracking, including taints, cmps.  Only set in LLVM mode.")
            .takes_value(true))
        .arg(Arg::with_name("pargs")
            .help("Targeted program (USE_FAST) and arguments. Any \"@@\" will be substituted with the input filename from Angora.")
            .required(true)
            .multiple(true)
            .allow_hyphen_values(true)
            .last(true)
            .index(1))
        .arg(Arg::with_name("memory_limit")
            .short("M")
            .long("memory_limit")
            .value_name("MEM")
            .help("Memory limit for programs, default is 200(MB), set 0 for unlimit memory")
            .takes_value(true))
        .arg(Arg::with_name("startup_time_limit")
            .short("U")
            .long("startup_time_limit")
            .value_name("STARTUP_TIME")
            .help(format!("time limit for programs to startup, default is {}µs, the tracking timeout is 12 * STARTUP_TIME", STARTUP_TIME_LIMIT).as_str())
            .takes_value(true))
        .arg(Arg::with_name("response_time_limit")
            .short("R")
            .long("response_time_limit")
            .value_name("RESPONSE_TIME")
            .help(format!("time limit for programs to respond, default is {}µs, the tracking timeout is 12 * RESPONSE_TIME", RESPONSE_TIME_LIMIT).as_str())
            .takes_value(true))
        .arg(Arg::with_name("thread_jobs")
            .short("j")
            .long("jobs")
            .value_name("JOB")
            .help("Sets the number of thread jobs, default is 1")
            .takes_value(true))
        .arg(Arg::with_name("search_method")
            .short("r")
            .long("search_method")
            .value_name("SearchMethod")
            .help("Which search method to run the program in?")
            .possible_values(&["gd", "random", "mb"]))
        .arg(Arg::with_name("sync_afl")
            .short("S")
            .long("sync_afl")
            .help("Sync the seeds with AFL. Output directory should be in AFL's directory structure."))
        .arg(Arg::with_name("disable_afl_mutation")
            .short("A")
            .long("disable_afl_mutation")
            .help("Disable the fuzzer to mutate inputs using AFL's mutation strategies"))
        .arg(Arg::with_name("disable_exploitation")
            .short("E")
            .long("disable_exploitation")
            .help("Disable the fuzzer to mutate sensitive bytes to exploit bugs"))
        .arg(Arg::with_name("disable_amp_mutation")
            .short("P")
            .long("disable_amp_mutation")
            .help("Disable the fuzzer to mutate inputs towards higher amplification ratio"))
        .arg(Arg::with_name("cfg_file")
            .short("c")
            .long("cfg")
            .value_name("TARGET_FILE")
            .help("Input file with targets and cfg (JSON file)")
            .required(true)
            .takes_value(true))
        .arg(Arg::with_name("only_directed")
            .short("D")
            .long("only_directed")
            .help("Only consider CMPs that have a path to one of the targets (Warn: only use if static CFG is sufficient.)"))
        .arg(Arg::with_name("target_addr")
            .long("target_addr")
            .value_name("TARGET_IP:PORT")
            .help("Address and port of target")
            .required(true)
            .takes_value(true))
        .arg(Arg::with_name("disable_listen_ready")
            .short("L")
            .long("disable_listen_ready")
            .help("Disable waiting for the target to reach a listening state"))
        .arg(Arg::with_name("early_termination")
            .long("early_termination")
            .value_name("EARLY_TERMINATION_MODE")
            .help("Mode of early termination (none, dynamic, static, full)")
            .takes_value(true))
        .get_matches();

    fuzz_main(
        matches.value_of("mode").unwrap_or("llvm"),
        matches.value_of("input_dir").unwrap(),
        matches.value_of("output_dir").unwrap(),
        matches.value_of("track_target").unwrap_or("-"),
        matches.values_of_lossy("pargs").unwrap(),
        value_t!(matches, "thread_jobs", usize).unwrap_or(1),
        value_t!(matches, "memory_limit", u64).unwrap_or(angora_common::config::MEM_LIMIT),
        value_t!(matches, "startup_time_limit", u64).unwrap_or(angora_common::config::STARTUP_TIME_LIMIT),
        value_t!(matches, "response_time_limit", u64).unwrap_or(angora_common::config::RESPONSE_TIME_LIMIT),
        matches.value_of("search_method").unwrap_or("gd"),
        matches.occurrences_of("sync_afl") > 0,
        matches.occurrences_of("disable_afl_mutation") == 0,
        matches.occurrences_of("disable_exploitation") == 0,
        matches.occurrences_of("disable_amp_mutation") == 0,
        matches.value_of("cfg_file").unwrap(),
        matches.occurrences_of("only_directed") > 0,
        matches.value_of("target_addr").unwrap(),
        matches.occurrences_of("disable_listen_ready") == 0,
        value_t!(matches.value_of("early_termination"), EarlyTermination).unwrap_or(EarlyTermination::Full),
    );
}
