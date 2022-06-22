#!/bin/bash
set -eux
PORT=$1
TARGET=$2

WRAP_BASE="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"

OUT="${TARGET}.wrap.${PORT}"

if [ ! -f "${TARGET}" ]; then
  >&2 echo "Cannot find ${TARGET}"
  exit 1
fi

cat >${OUT} <<EOF
#!/bin/bash
# Make symbolic executor believe this is a binary:
LD_PRELOAD=${WRAP_BASE}/libioctl_shim.so exec ${WRAP_BASE}/inetd_wrap ${PORT} ${TARGET}
EOF
chmod +x ${OUT}