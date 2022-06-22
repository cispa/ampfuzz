#!/bin/bash
set -eux
export LC_ALL=C

PATTERN_FILE="patterns.csv"
RAW_PATTERN_FILE="patterns.txt"
MATCH_FILE="matches.txt"

regex_name="^network_port\((.*),$"
regex_port="^udp,([0-9-]+),.*$"
regex_last="^.*\)$"
regex_type="^.*_port\((.*)_t\)$"

ports=""
name=""

rm -f ${PATTERN_FILE}

pushd apt-file-docker
docker build -t apt-file .
popd

grep -hr '^network_port(' | 
while IFS= read -r line;
do
	ports=""
	name=""
	for token in $line
	do
		if [[ $token =~ $regex_name ]]
		then
			name="${BASH_REMATCH[1]}"
		elif [[ $token =~ $regex_port ]]
		then
			ports="${ports},${BASH_REMATCH[1]}"
		fi

		if [[ $token =~ $regex_last && $ports != "" ]]
		then

			grep -hr -w 'corenet_udp_.*_'"${name}"'_port'|
			while IFS= read -r corenet_line;
			do
				if [[ $corenet_line =~ $regex_type ]]
				then
					typename="${BASH_REMATCH[1]}"
					exectypename="${typename}_exec_t"

					grep -hr -w "${exectypename}"  --include='*fc'|
						while IFS= read -r path_line;
						do
							binpattern="${path_line%%[[:space:]]*}"
							echo "${name};${ports};^${binpattern}$" >> ${PATTERN_FILE}
						done
				fi
			done

		fi
	done
done

cut -d';' -f3 ${PATTERN_FILE}|sort -u|sed -n 'p;s/\/usr\//\//;T;p'|sort -u > ${RAW_PATTERN_FILE}
docker run -i apt-file -x -f- search < ${RAW_PATTERN_FILE} | sed -e 's/[[:space:]]*$//' > ${MATCH_FILE}
