all:
	@$(MAKE) -C 01_collect_targets
	@$(MAKE) -C 02_filter_matches
	@$(MAKE) -C 03_join_matches
	@$(MAKE) -C 04_create_eval_dir

.PHONY: clean

clean:
	@$(MAKE) -C 01_collect_targets clean
	@$(MAKE) -C 02_filter_matches clean
	@$(MAKE) -C 03_join_matches clean
	@$(MAKE) -C 04_create_eval_dir clean
