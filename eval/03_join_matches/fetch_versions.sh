#!/bin/bash
set -eux
export LC_ALL=C

MATCH_FILE="matches.txt"
VERSIONS_FILE="versions.txt"

pushd ../01_collect_targets/apt-file-docker
docker build -t apt-file .
popd

TMPDIR=$(mktemp -d)
TMP_MATCHES="${TMPDIR}/matches"
TMP_DONE="${TMPDIR}/done"
TMP_NEW="${TMPDIR}/new"
TMP_OLD="${TMPDIR}/old"

if [ ! -f ${VERSIONS_FILE} ]
then
	touch ${VERSIONS_FILE}
fi

cut -d':' -f1 ${MATCH_FILE} | sort -u >${TMP_MATCHES}
if [ -f ${VERSIONS_FILE} ]; then
  cut -d'=' -f1 ${VERSIONS_FILE} | sort -u >${TMP_DONE}
else
  touch ${TMP_DONE}
fi

for pkg in $(comm -23 ${TMP_MATCHES} ${TMP_DONE}); do
  docker run -ti --entrypoint apt-cache apt-file show ${pkg} | grep '^Version:' | sed 's/Version:[[:space:]]*\(.*\)$/'${pkg}'=\1/g' | head -n1 | tr -d \\r
done >${TMP_NEW}

cp ${VERSIONS_FILE} ${TMP_OLD}

cat ${TMP_OLD} ${TMP_NEW} | sort -u >${VERSIONS_FILE}

rm -rf ${TMPDIR}
