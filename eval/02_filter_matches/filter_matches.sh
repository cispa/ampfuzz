#!/bin/bash
set -eux
export LC_ALL=C

OLD_MATCH_FILE="old_matches.txt"
MATCH_FILE="matches.txt"
FALSE_POSITIVES_FILE="false_positives.txt"
MANUAL_FALSE_POSITIVES_FILE="false_positives_manual.txt"
TRUE_POSITIVES_FILE="true_positives.txt"

TMPDIR=$(mktemp -d)

TMP_OLD_MATCH_FILE="${TMPDIR}/old_matches_sorted"
TMP_FALSE_POSITIVES_FILE="${TMPDIR}/false_positives_sorted"
TMP_TRUE_POSITIVES_FILE="${TMPDIR}/true_positives_sorted"
TODO_FILE="${TMPDIR}/todo"
TMP_RESULT_CACHE="${TMPDIR}/result.cached"
TMP_RESULT_NON_CACHE="${TMPDIR}/result.non_cached"
TMP_NEW_FALSE_POSITIVES="${TMPDIR}/false_positives_new"

pushd package-check-docker
docker build -t package-check .
popd

# sort matches
sort -u ${OLD_MATCH_FILE} >${TMP_OLD_MATCH_FILE}
# sort cache files
sort -u ${FALSE_POSITIVES_FILE} ${MANUAL_FALSE_POSITIVES_FILE} >${TMP_FALSE_POSITIVES_FILE}
sort -u ${TRUE_POSITIVES_FILE} | comm -23 - ${TMP_FALSE_POSITIVES_FILE} >${TMP_TRUE_POSITIVES_FILE}
# compute actual TODO
comm -23 ${TMP_OLD_MATCH_FILE} ${TMP_FALSE_POSITIVES_FILE} | comm -23 - ${TMP_TRUE_POSITIVES_FILE} >${TODO_FILE}
# compute results from cache
comm -12 ${TMP_OLD_MATCH_FILE} ${TMP_TRUE_POSITIVES_FILE} >${TMP_RESULT_CACHE}
# compute results not in cache
docker run -i package-check <${TODO_FILE} | sort -u >${TMP_RESULT_NON_CACHE}
# combine both
sort -u ${TMP_RESULT_CACHE} ${TMP_RESULT_NON_CACHE} >${MATCH_FILE}
# update cache files
comm -23 ${TODO_FILE} ${TMP_RESULT_NON_CACHE} >${TMP_NEW_FALSE_POSITIVES}
sort -u ${TMP_FALSE_POSITIVES_FILE} ${TMP_NEW_FALSE_POSITIVES} >${FALSE_POSITIVES_FILE}
sort -u ${TMP_TRUE_POSITIVES_FILE} ${TMP_RESULT_NON_CACHE} >${TRUE_POSITIVES_FILE}

# clean up
rm -rf ${TMPDIR}
