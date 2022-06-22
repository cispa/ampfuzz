#!/bin/bash
set -eux

OUT_DIR=$1
FUZZ_BASE_IID_FILE=$(realpath "$2")
TARGET=$3
FUZZ_TARGET_IID_FILE=$(realpath "$4")

TARGET_CID_FILE=${FUZZ_TARGET_IID_FILE%%.iid}.cid
BASE_IID=$(cat "${FUZZ_BASE_IID_FILE}")


docker volume create ampfuzz_build_cache

# perform arcane magic:
# docker does not allow mounting volumes during build,
# therefore we emulate the build by running in a fresh container
# and then committing this container to a new image.
# Since we override the cmd and entrypoint during run,
# we need to "revert" these changes during commit

extraargs=""
if [[ -v ANGORA_EARLY_TERMINATION ]]; then
  extraargs="-e ANGORA_EARLY_TERMINATION=${ANGORA_EARLY_TERMINATION}"
fi

docker run -v ampfuzz_build_cache:/var/ampfuzz:ro ${extraargs} --cidfile "${TARGET_CID_FILE}" ${BASE_IID} python 02_instrument_target.py "${TARGET}"
docker commit -c 'CMD ["/bin/bash"]' $(cat ${TARGET_CID_FILE}) > ${FUZZ_TARGET_IID_FILE}
