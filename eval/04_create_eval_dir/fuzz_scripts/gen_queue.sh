#!/bin/bash
set -eu

RESULT_BASE="results"

to_csv () {
  python3 <<EOF
import json
with open("$1") as f:
    l = json.load(f)
for x in l:
    print(";".join(map(str,x)))
EOF
}

while IFS=';' read pkg binary port
do
  while read out_slug args
  do
    if [[ "${out_slug}" =~ ^#.* ]]
    then
      continue
    fi
    echo "${pkg} ${binary} ${port} ${RESULT_BASE}/${pkg}/${binary//\//_}_${port}/${out_slug} ${args}"
  done < args
done <<< $(to_csv targets.json)