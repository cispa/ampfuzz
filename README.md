# AMPFUZZ: Fuzzing for Amplification DDoS Vulnerabilities

## Requirements
* [docker](https://www.docker.com)
* python3

## Usage
 
### 1. Build docker base images
from the project directory, run
```bash
make
```

This will take some time and build four docker images:
* `ampfuzz:base`: serves as the base-image for the other three stages, basically a Ubuntu 20.10 image with some packages installed and including a copy of the llvm source.
* `ampfuzz:wllvm_wrapper`: used to build ubuntu packages with `wllvm`, a the whole-program LLVM wrapper. Our later stages use `wllvm` to extract LLVM bitcode from installed packages.
* `ampfuzz:fuzzer`: includes the fuzzer and required instrumentation tools.
* `ampfuzz:symbolic_execution`: includes the symcc symbolic execution engine, and is used to instrument targets and replay the amplification inputs to collect path constraints.

### 2. Prepare Evaluation Directory
from the `eval` subdirectory, run
```bash
make
```

This will generate a fresh evaluation directory in `eval/04_create_eval_dir/eval`.
The resulting directory can be moved around freely and should contain everything required to proceed.

#### 2.1 Adjust eval parameters
Evaluation is controlled by two files, `args` and `fuzz_all.sh`.
`args` contains the different fuzzing configurations, one per line, in the following format
```
<output_directory> <timeout> [extra_args ...]
```
E.g., the two lines
```
1h 1h
1h_100ms 1h -a=--disable_listen_ready -a=--early_termination=none -a=--startup_time_limit=100000 -a=--response_time_limit=100000
```
will run 
1. a default configuration for one hour and store the results into directory `1h`
2. a configuration with a static timeout of 100ms and store the results into directory `1h_100ms`

The `fuzz_all.sh` script further specifies how often each experiment should be repeated.
This is controlled with the `N_RUNS` variable (defaults to `5`).

### 3. Fuzz 
Running `fuzz_all.sh` will now
1. use the generated `Makefile` to prepare all targets for fuzzing (i.e., building and instrumenting the target into individual docker images)
2. fuzz each target with each configuration and collect all results into a new `results` directory
3. run the paths-to-message deduplication script.
   This script collects all unique "paths" found during fuzzing and executes them against the dataflow-instrumented target binary, collecting only request-dependent CFG edges.

For each target and run, a new subfolder will be created of the form `results/<pkg>/<binary>_<port>/<run>`.

### 4. Analyze results
Once fuzzing and path-deduplication has completed, the new `results` directory can be analyzed:
1. `eval_scripts/01_compute_amp_stats.py` will extract final stats for each run into a file `results/results.json`
2. `eval_scripts/02_print_table.py` will generate latex code for the overview table shown in the paper
3. `eval_scripts/03_plot_grid.py` will generate the plots to show the results of different timeouts and amplification maximization runs

### (optional) 5. generate honeypot code
Prepare a target for symbolic execution, run constraint-collection for a run folder (`results/<pkg>/<binary>_<port>/<config>/<run>`), and convert the collected constraints to python code:
1. `make targets/<pkg>/.sym_config_<path>_<port>.iid` will build a docker-container and instrumenting the target for symbolic execution.
2. `bash hpsynth_scripts/synth_one.sh <run_folder>` will create a constraints file named `hpsynth/sym.result` in the run folder.
3. `python hpsynth_scripts/main.py <sym.result>` will output python code for a number of `check` and `output` functions, along with a combined `gen_reply` function.

(Honeypot-skeleton for listening on ports and providing rate-limiting is not provided with this project)
