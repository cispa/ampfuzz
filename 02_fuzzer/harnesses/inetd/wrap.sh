#!/bin/bash
set -eux
PORT=$1
TARGET=$2

WRAP_BASE="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"

FAST_TARGET="${TARGET}.fast"
TRACK_TARGET="${TARGET}.track"

FAST_OUT="${TARGET}.wrap.${PORT}.fast"
TRACK_OUT="${TARGET}.wrap.${PORT}.track"

if [ ! -f "${FAST_TARGET}" ] || [ ! -f "${TRACK_TARGET}" ]; then
  >&2 echo "Cannot find ${FAST_TARGET} or ${TRACK_TARGET},"
  >&2 echo "Please instrument ${TARGET} first"
  exit 1
fi

cat >${FAST_OUT} <<EOF
#!/bin/bash
# Make fuzzer believe this is a .fast binary:
# __angora_cond_cmpid
LD_PRELOAD=${WRAP_BASE}/libioctl_shim.so exec ${WRAP_BASE}/inetd_wrap ${PORT} ${FAST_TARGET}
EOF
chmod +x ${FAST_OUT}

cat >${TRACK_OUT} <<EOF
#!/bin/bash
# Make fuzzer believe this is a .track binary:
# __dfsw___angora_trace_cmp_tt
LD_PRELOAD=${WRAP_BASE}/libioctl_shim.so exec ${WRAP_BASE}/inetd_wrap ${PORT} ${TRACK_TARGET}
EOF
chmod +x ${TRACK_OUT}