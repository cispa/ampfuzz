#!/bin/bash
set -eu

SCRIPTPATH="$(realpath $( cd -- "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 ; pwd -P ))"
export SCRIPTPATH

MAX_PROCS=$(nproc)

function json_get {
  json_file="$1"
  key="$2"
  python3 -c "import json;print(json.load(open('${json_file}')).get('${key}',''))"
}

function dedup_one {
  angora_log=$1
  result_dir=$(dirname "${angora_log}")
  fuzz_cfg="${result_dir}/fuzz.cfg"
  if [ ! -f ${fuzz_cfg} ]
  then
    echo "Config file ${fuzz_cfg} missing, cannot determine docker image ID, aborting!"
    retun 1
  fi

  iid=$(json_get ${fuzz_cfg} iid)

  dedup_dir="${result_dir}/dedup_results"
  if [ -d ${dedup_dir} ]
  then
    # Slightly disgusting hack:
    # Attempt to remove directory. This will only succeed if the directory was truly empty.
    rmdir "${dedup_dir}" --ignore-fail-on-non-empty
  fi

  # Still exists? -> directory was non-empty
  if [ -d ${dedup_dir} ]
    then
    echo "Non-empty dedup directory ${dedup_dir} already exists, skipping"
  else
    echo "Now de-duplicating ${dedup_dir}..."
    cid_file="${result_dir}/.dedup_cid"
    if [ -f ${cid_file} ]
    then
      rm "${cid_file}"
    fi

    docker run --cidfile=${cid_file} -v $(realpath ${result_dir}):/fuzz_run:ro -v $(realpath ${SCRIPTPATH}/dedup_results.py):/dedup_results.py:ro "${iid}" python /dedup_results.py
    if [ -f ${cid_file} ]
      then
      docker cp $(cat ${cid_file}):/dedup_results "${dedup_dir}"
    fi
  fi

}

export -f json_get
export -f dedup_one

find results/ -name 'angora.log' -print0|xargs -0 -n 1 -P ${MAX_PROCS} bash -c 'dedup_one "$@"' _