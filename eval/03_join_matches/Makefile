all: package_matches.json


package_matches.json: patterns.csv matches.txt versions.txt by_inst join_matches_packages.py
	python3 join_matches_packages.py

patterns.csv: ../01_collect_targets/patterns.csv
	ln -sf ../01_collect_targets/patterns.csv

matches.txt: ../02_filter_matches/matches.txt
	ln -sf ../02_filter_matches/matches.txt

versions.txt: matches.txt fetch_versions.sh
	bash fetch_versions.sh

by_inst:
	wget https://popcon.debian.org/main/by_inst

.PHONY: clean fullclean

clean:
	rm -rf package_matches.json patterns.csv matches.txt versions.txt

fullclean: clean
	rm -rf by_inst
