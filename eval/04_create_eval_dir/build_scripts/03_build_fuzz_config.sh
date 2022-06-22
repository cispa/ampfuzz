#!/bin/bash
set -eux

OUT_DIR=$1
FUZZ_TARGET_IID_FILE=$(realpath "$2")
PKG=$3
TARGET=$4
TARGETNAME=${TARGET//\//_}
PORT=$5
FUZZ_CONFIG_IID_FILE=$(realpath "$6")
ARGS_FILE="args"
CONFIG_SCRIPT="config.sh"
FUZZ_ARGS_FILE="fuzz_args"
FUZZ_SCRIPT="fuzz.sh"
FUZZ_DOCKERFILE="fuzz.dockerfile"

FUZZ_TARGET_IID=$(cat "${FUZZ_TARGET_IID_FILE}")

configdir="${OUT_DIR}/${TARGETNAME}/${PORT}"
mkdir -p ${configdir}
pushd ${configdir}

if [ ! -f "${CONFIG_SCRIPT}" ]; then
  cat >"${CONFIG_SCRIPT}" <<EOF
#!/bin/sh
# AmpFuzz pre-fuzz config script
# Use this script to create/modify
# config files for the fuzz target
EOF
fi

args=""
if [ -f "${ARGS_FILE}" ]; then
  args=$(cat ${ARGS_FILE}|tr '[:space:]' ' ')
fi

fuzz_args=""
if [ -f "${FUZZ_ARGS_FILE}" ]; then
  fuzz_args=$(cat ${FUZZ_ARGS_FILE}|tr '[:space:]' ' ')
fi

cat > ${FUZZ_SCRIPT} <<EOF
#!/bin/bash
python /02_fuzzer/03_fuzz_target.py \$@ ${fuzz_args} "${TARGET}" "${PORT}" -- ${args}
EOF

cat > "${FUZZ_DOCKERFILE}" <<EOF
FROM ${FUZZ_TARGET_IID}
COPY ${CONFIG_SCRIPT} ${FUZZ_SCRIPT} /
RUN chmod +x /${CONFIG_SCRIPT} /${FUZZ_SCRIPT}
RUN /${CONFIG_SCRIPT}
WORKDIR /
LABEL "port"="${PORT}"
EOF

docker build --cpu-quota=100000 --iidfile "${FUZZ_CONFIG_IID_FILE}" -f "${FUZZ_DOCKERFILE}" .

popd