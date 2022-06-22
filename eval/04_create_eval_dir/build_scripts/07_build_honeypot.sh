#!/bin/bash
set -eux
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)/../hpsynth_scripts"

# ensure virtualenv is present
VENV_DIR="${SCRIPT_DIR}/.venv"
if [ ! -d ${VENV_DIR} ]
then
  python3 -m venv ${VENV_DIR}
fi
source "${VENV_DIR}/bin/activate"
python3 -m pip install -r ${SCRIPT_DIR}/requirements.txt

# ensure output directory is present
OUT_DIR=results/honeypot
if [ ! -d ${OUT_DIR} ]
then
  mkdir -p ${OUT_DIR}
fi

# generate handlers
for sym_file in $(find results/ -name 'sym.result' -path '*/hpsynth/*' )
do
  echo "Found file ${sym_file}"
  if [[ $sym_file =~ results/[^/]*/(.+)_([0-9]+)/.* ]]
  then
    program=${BASH_REMATCH[1]}
    port=${BASH_REMATCH[2]}
    echo "Program ${program} on port ${port}"
    python3 ${SCRIPT_DIR}/main.py ${sym_file} ${program} ${port} > "${OUT_DIR}/${program}_${port}.py"
  fi
done

deactivate
