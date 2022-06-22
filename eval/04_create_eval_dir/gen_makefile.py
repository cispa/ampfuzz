        #!/usr/bin/env python3
    # coding: utf-8

import json
import os

with open('package_matches.json') as f:
    packages = json.load(f)

if os.path.exists('final_eval.json'):
    with open('final_eval.json') as f:
        final_eval = set(tuple(x) for x in json.load(f))
else:
    final_eval = set()

pkg_rules = []
target_rules = []
fuzz_prep_rules = []
fuzz_prep_targets_final = []
sym_prep_rules = []
sym_prep_targets_final = []

targets_dir = "targets"
script_dir = "build_scripts"

for pkg, pkg_info in sorted(packages.items()):
    pkg_dir = os.path.join(targets_dir, pkg)
    version = pkg_info['version']
    # add package-specific rules'
    fuzz_base_slug = "fuzz_base"
    fuzz_base_iid_file = os.path.join(pkg_dir, f".{fuzz_base_slug}.iid")
    fuzz_base_log_file = os.path.join(pkg_dir, f"build_{fuzz_base_slug}.log")
    fuzz_base_script = os.path.join(script_dir, "01_build_fuzz_base.sh")
    pkg_rules.append((fuzz_base_iid_file,
                      [],
                      [f"mkdir -p {pkg_dir}",
                       f"bash {fuzz_base_script} {pkg_dir} {pkg} \"{version}\" $@ 2>&1 | tee {fuzz_base_log_file}"]))

    sym_base_slug = "sym_base"
    sym_base_iid_file = os.path.join(pkg_dir, f".{sym_base_slug}.iid")
    sym_base_log_file = os.path.join(pkg_dir, f"build_{sym_base_slug}.log")
    sym_base_script = os.path.join(script_dir, "04_build_sym_base.sh")
    pkg_rules.append((sym_base_iid_file,
                      [],
                      [f"mkdir -p {pkg_dir}",
                       f"bash {sym_base_script} {pkg_dir} {pkg} \"{version}\" $@ 2>&1 | tee  {sym_base_log_file}"]))

    binaries = pkg_info['binaries']
    for binary, ports in sorted(binaries.items()):
        # add target-specific rules
        target_name = binary.replace('/', '_')
        fuzz_target_slug = f"fuzz_target_{target_name}"
        fuzz_target_iid_file = os.path.join(pkg_dir, f".{fuzz_target_slug}.iid")
        fuzz_target_log_file = os.path.join(pkg_dir, f"build_{fuzz_target_slug}.log")
        fuzz_target_script = os.path.join(script_dir, "02_build_fuzz_target.sh")
        target_rules.append((fuzz_target_iid_file,
                             [fuzz_base_iid_file],
                             [
                                 f"bash {fuzz_target_script} {pkg_dir} {fuzz_base_iid_file} {binary} $@ 2>&1 | tee {fuzz_target_log_file}"]))

        sym_target_slug = f"sym_target_{target_name}"
        sym_target_iid_file = os.path.join(pkg_dir, f".{sym_target_slug}.iid")
        sym_target_log_file = os.path.join(pkg_dir, f"build_{sym_target_slug}.log")
        sym_target_script = os.path.join(script_dir, "05_build_sym_target.sh")
        target_rules.append((sym_target_iid_file,
                             [sym_base_iid_file],
                             [
                                 f"bash {sym_target_script} {pkg_dir} {sym_base_iid_file} {binary} $@ 2>&1 | tee {sym_target_log_file}"]))

        for port in sorted(ports):
            # add config-specific rules

            # prepare config for fuzzing
            fuzz_config_slug = f"fuzz_config_{target_name}_{port}"
            fuzz_config_iid_file = os.path.join(pkg_dir, f".{fuzz_config_slug}.iid")
            fuzz_config_log_file = os.path.join(pkg_dir, f"build_{fuzz_config_slug}.log")
            fuzz_config_script = os.path.join(script_dir, "03_build_fuzz_config.sh")
            fuzz_prep_rules.append((fuzz_config_iid_file,
                                    [fuzz_target_iid_file],
                                    [
                                        f"bash {fuzz_config_script} {pkg_dir} {fuzz_target_iid_file} {pkg} {binary} {port} $@ 2>&1 | tee {fuzz_config_log_file}"]))

            # prepare config for honeypot synthesis
            sym_config_slug = f"sym_config_{target_name}_{port}"
            sym_config_iid_file = os.path.join(pkg_dir, f".{sym_config_slug}.iid")
            sym_config_log_file = os.path.join(pkg_dir, f"{sym_config_slug}.log")
            sym_config_script = os.path.join(script_dir, "06_build_sym_config.sh")
            sym_prep_rules.append((sym_config_iid_file,
                                   [sym_target_iid_file],
                                   [
                                       f"bash {sym_config_script} {pkg_dir} {sym_target_iid_file} {pkg} {binary} {port} $@ 2>&1 | tee {sym_config_log_file}"]))

            if (pkg, binary, port) in final_eval:
                fuzz_prep_targets_final.append(fuzz_prep_rules[-1][0])
                sym_prep_targets_final.append(sym_prep_rules[-1][0])

variables = {'TIMEOUT': '60s'}

top_rules = []
build_rules = []

# add rules for final eval
top_rules.append(("all", ["fuzz"], []))

top_rules.append(("sym_prep_final", sym_prep_targets_final, []))
top_rules.append(("fuzz_prep_final", fuzz_prep_targets_final, []))

# add rules for individual stages
top_rules.append(("sym_prep", [r[0] for r in sym_prep_rules], []))
top_rules.append(("fuzz_prep", [r[0] for r in fuzz_prep_rules], []))
top_rules.append(("instrument", [r[0] for r in target_rules], []))
top_rules.append(("build", [r[0] for r in pkg_rules], []))


top_rules.append((".PHONY", ["clean", "honeypot"], []))
# add rule for "clean"
top_rules.append(("clean", [], ["find . -name '*.iid' -delete"]))
# add rule for honeypot synthesis
top_rules.append(("honeypot", ["$(shell find targets/ -name 'sym_run_*' ! -name '*\\.log')"],
                  [f"bash {os.path.join(script_dir, '07_build_honeypot.sh')}"]))

build_rules.extend(pkg_rules)
build_rules.extend(target_rules)
build_rules.extend(fuzz_prep_rules)
build_rules.extend(sym_prep_rules)


def print_rules(rules):
    for rule in rules:
        rule_name, rule_deps, rule_cmds = rule
        assert len(rule_name.split()) == 1
        print(f"{rule_name} : {' '.join(rule_deps)}")
        for cmd in rule_cmds:
            print(f"\t{cmd}")
        print("")


for variable, value in variables.items():
    print(f"{variable}={value}")
print("")

print_rules(top_rules)
print_rules(build_rules)
