#!/bin/bash
set -eux

OUT_DIR=$1
PKG=$2
VERSION=$3
FUZZ_BASE_IID_FILE=$(realpath "$4")

FUZZ_BASE_CID_FILE=${FUZZ_BASE_IID_FILE%%.iid}.cid
VERSION_FILE="${OUT_DIR}/version"

docker volume create ampfuzz_build_cache

# build package with our wllvm wrapper
docker run -v ampfuzz_build_cache:/var/ampfuzz --label "pkg=${PKG}" ampfuzz:wllvm_wrapper python 01_prep_package.py -v "${VERSION}" "${PKG}"

# perform arcane magic:
# docker does not allow mounting volumes during build,
# therefore we emulate the build by running in a fresh container
# and then committing this container to a new image.
# Since we override the cmd and entrypoint during run,
# we need to "revert" these changes during commit

docker run -v ampfuzz_build_cache:/var/ampfuzz:ro --cidfile "${FUZZ_BASE_CID_FILE}" --label "pkg=${PKG}" ampfuzz:fuzzer python 01_install_package.py -v "${VERSION}" "${PKG}"
docker commit -c 'CMD ["/bin/bash"]' $(cat ${FUZZ_BASE_CID_FILE}) > ${FUZZ_BASE_IID_FILE}