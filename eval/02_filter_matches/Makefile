all: matches.txt


matches.txt: old_matches.txt filter_matches.sh false_positives_manual.txt package-check-docker/*
	bash filter_matches.sh

old_matches.txt: ../01_collect_targets/matches.txt
	ln -sf ../01_collect_targets/matches.txt old_matches.txt

.PHONY: clean

clean: 
	rm -rf old_matches.txt matches.txt
