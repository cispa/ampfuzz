all: matches.txt patterns.csv


matches.txt patterns.csv patterns.txt &: refpolicy extract_packages.sh apt-file-docker/*
	bash extract_packages.sh

refpolicy: 
	git clone https://github.com/SELinuxProject/refpolicy.git

.PHONY: clean fullclean

clean:
	rm -rf matches.txt patterns.csv patterns.txt

fullclean: clean
	rm -rf refpolicy
