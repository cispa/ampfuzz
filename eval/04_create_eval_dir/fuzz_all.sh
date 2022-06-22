#!/bin/bash
set -eu

MAX_PROCS=$(nproc)
N_RUNS=5

make -j ${MAX_PROCS} fuzz_prep_final

if [ ! -f queue ] || [ ! -s queue ]
then
  for run in $(seq ${N_RUNS})
  do
    bash fuzz_scripts/gen_queue.sh|shuf|sed "s/^/-r ${run} /" >> queue
  done
fi

xargs -t -a queue -L 1 -P ${MAX_PROCS} bash fuzz_scripts/fuzz_one.sh
bash fuzz_scripts/dedup_results_outer.sh