#!/bin/bash
set -eux

OUT_DIR=$1
SYM_TARGET_IID_FILE=$(realpath "$2")
PKG=$3
TARGET=$4
TARGETNAME=${TARGET//\//_}
PORT=$5
SYM_CONFIG_IID_FILE=$(realpath "$6")
ARGS_FILE="args"
CONFIG_SCRIPT="config.sh"
FUZZ_ARGS_FILE="fuzz_args"
SYM_SCRIPT="sym.sh"
SYM_DOCKERFILE="sym.dockerfile"

SYM_TARGET_IID=$(cat "${SYM_TARGET_IID_FILE}")

configdir="${OUT_DIR}/${TARGETNAME}/${PORT}"

pushd ${configdir}

args=""
if [ -f "${ARGS_FILE}" ]; then
  args=$(cat ${ARGS_FILE}|tr '[:space:]' ' ')
fi

fuzz_args=""
if [ -f "${FUZZ_ARGS_FILE}" ]; then
  fuzz_args=$(cat ${FUZZ_ARGS_FILE}|tr '[:space:]' ' ')
fi

cat > ${SYM_SCRIPT} <<EOF
#!/bin/bash
python /03_symbolic_execution/03_collect_constraints.py ${fuzz_args} "${TARGET}" "${PORT}" -- ${args}
EOF

cat > "${SYM_DOCKERFILE}" <<EOF
FROM ${SYM_TARGET_IID}
COPY ${CONFIG_SCRIPT} ${SYM_SCRIPT} /
RUN chmod +x /${CONFIG_SCRIPT} /${SYM_SCRIPT}
RUN /${CONFIG_SCRIPT}
WORKDIR /
LABEL "port"="${PORT}"
EOF

docker build --cpu-quota=100000 --iidfile "${SYM_CONFIG_IID_FILE}" -f "${SYM_DOCKERFILE}" .

popd
