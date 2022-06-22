#!/bin/bash
set -eux

SERVICE_DIR=$1
SERVICE=$(basename ${SERVICE_DIR})
find ${SERVICE_DIR} -name args -or -name config.sh -or -name fuzz_args|xargs git add -f
git commit -m "add args/config for ${SERVICE}"
