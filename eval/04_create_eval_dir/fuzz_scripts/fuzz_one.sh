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
FUZZ_LOG="fuzz.log"

json_escape () {
	echo -n "$@"|python3 -c 'import json,sys;print(json.dumps(sys.stdin.read()))'
}

run_slug="00"
if [ "$1" = "-r" ]
then
  run_slug=$(printf "%02d" $2)
  shift 2
fi

if [ $# -lt 5 ]
then
	>&2 echo "Usage: $0 [-r run] <pkg> <path> <port> <output director> <timeout> [extra fuzz args...]"
	exit 1
fi

pkg="$1"
target_binary="$2"
port="$3"
shift 3

iidfile="./targets/${pkg}/.fuzz_config_${target_binary//\//_}_${port}.iid"
if [ ! -f "${iidfile}" ]
then
	>&2 echo "iid-file ${iidfile} does not exist, aborting!"
	exit 2
fi
iid=$(cat "${iidfile}")
if [ $(docker inspect "${iid}" >/dev/null 2>&1) ]
then
	>&2 echo "Docker image ${iid} does not exist, aborting!"
	exit 3
fi

outputdir="$1/${run_slug}"
if [ ! -z "$(ls -A ${outputdir} 2>/dev/null)" ]
then
	>&2 echo "Output directory ${outputdir} is non-empty, aborting!"
	exit 4
fi
mkdir -p "${outputdir}"
pushd ${outputdir} >/dev/null
shift

timeout="${1:-15m}"
shift

echo -e "{\"pkg\": $(json_escape ${pkg}), \"target\": $(json_escape ${target_binary}), \"port\": $(json_escape ${port}), \"iid\": $(json_escape ${iid}), \"output\": $(json_escape ${outputdir}), \"timeout\": $(json_escape ${timeout}), \"args\": $(json_escape $@)}" > "${FUZZ_CONFIG}"

docker run --cpu-quota=${CPU_QUOTA} --cidfile "${CID_FILE}" ${iid} timeout ${timeout} /fuzz.sh $@ 2>&1 > "${FUZZ_LOG}" || true

if [ ! -f "${CID_FILE}" ]
then
	>&2 echo "Error starting docker container, check the log-file at $(readlink -f "${FUZZ_LOG}")"
	exit 5
fi
cid=$(cat "${CID_FILE}")
echo "CID: ${cid}"
if [ $(docker inspect "${cid}" >/dev/null 2>&1) ]
then
	>&2 echo "Docker container ${cid} does not exist, aborting!"
	exit 6
fi

docker cp "${cid}:${target_binary}.out/." .
popd >/dev/null
