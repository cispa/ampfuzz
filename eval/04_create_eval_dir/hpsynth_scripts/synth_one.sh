#!/bin/bash
set -eu
# This script executes *one* fuzzing run
# cmdline arguments arg
# 1. debian package name
# 2. fuzz-target path
# 3. fuzz port
# 4. an output folder
# 5. timeout
# 6.-x Additional arguments to the /fuzz.sh script within docker

CPU_QUOTA=200000
CID_FILE=".cid"
FUZZ_CONFIG="fuzz.cfg"
SYM_LOG="sym.log"

json_escape () {
	echo -n "$@"|python3 -c 'import json,sys;print(json.dumps(sys.stdin.read()))'
}

json_read () {
  python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get(sys.argv[2],""))' $@
}


if [ $# -lt 1 ]
then
	>&2 echo "Usage: $0 <output director>"
	exit 1
fi

output_dir="$1"
config_file="${output_dir}/${FUZZ_CONFIG}"

if [ ! -f "${config_file}" ]
then
  >&2 echo "Config file ${config_file} does not exist, aborting!"
  exit 2
fi

pkg=$(json_read "${config_file}" "pkg")
target_binary=$(json_read "${config_file}" "target")
port=$(json_read "${config_file}" "port")

iidfile="./targets/${pkg}/.sym_config_${target_binary//\//_}_${port}.iid"
if [ ! -f "${iidfile}" ]
then
	>&2 echo "iid-file ${iidfile} does not exist, aborting!"
	exit 3
fi
iid=$(cat "${iidfile}")
if [ $(docker inspect "${iid}" >/dev/null 2>&1) ]
then
	>&2 echo "Docker image ${iid} does not exist, aborting!"
	exit 4
fi

amp_dir=$(readlink -f "${output_dir}/amps")

sym_dir="$1/hpsynth"
if [ ! -z "$(ls -A ${sym_dir} 2>/dev/null)" ]
then
	>&2 echo "Output directory ${sym_dir} is non-empty, aborting!"
	exit 5
fi
mkdir -p "${sym_dir}"
pushd ${sym_dir} >/dev/null


docker run --cpu-quota=${CPU_QUOTA} --cidfile "${CID_FILE}" -v"${amp_dir}":/amps:ro ${iid} /sym.sh 2>&1 > "${SYM_LOG}" || true

if [ ! -f "${CID_FILE}" ]
then
	>&2 echo "Error starting docker container, check the log-file at $(readlink -f "${SYM_LOG}")"
	exit 5
fi
cid=$(cat "${CID_FILE}")
echo "CID: ${cid}"
if [ $(docker inspect "${cid}" >/dev/null 2>&1) ]
then
	>&2 echo "Docker container ${cid} does not exist, aborting!"
	exit 6
fi

docker cp "${cid}:${target_binary}.sym.result" "sym.result"

popd >/dev/null
