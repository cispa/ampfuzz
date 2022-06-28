all: eval/Makefile eval/build_scripts eval/hpsynth_scripts eval/targets eval/fuzz_scripts eval/eval_scripts eval/targets.json eval/fuzz_all.sh eval/args

eval :
	mkdir -p $@

eval/Makefile: package_matches.json gen_makefile.py $(wildcard final_eval.json)| eval
	python3 gen_makefile.py > $@

package_matches.json: ../03_join_matches/package_matches.json | eval
	ln -sf ../03_join_matches/package_matches.json $@

eval/build_scripts: $(wildcard build_scripts/*) | eval
	mkdir -p $@
	rsync -a build_scripts/ $@/

eval/hpsynth_scripts: $(wildcard hpsynth_scripts/*) | eval
	mkdir -p $@
	cp $? $@

eval/targets: targets | eval
	mkdir -p $@
	rsync -a targets/ $@/

eval/targets.json: final_eval.json | eval
	cp $? $@

eval/fuzz_scripts: $(wildcard fuzz_scripts/*) | eval
	mkdir -p $@
	rsync -a fuzz_scripts/ $@/

eval/eval_scripts: $(wildcard eval_scripts/*) | eval
	mkdir -p $@
	rsync -a eval_scripts/ $@/

eval/%: % | eval
	cp $? $@

.PHONY: clean

clean:
	rm -rf eval
