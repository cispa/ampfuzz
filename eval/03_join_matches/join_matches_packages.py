#!/usr/bin/env python3
# coding: utf-8
import json
import re


def parse_ports(p):
    ports = []
    for token in p.split(','):
        if not token:
            continue
        if '-' in token:
            lo, hi = map(int, token.split('-'))
            ports.extend(range(lo, hi + 1))
        else:
            ports.append(int(token))
    return ports


with open('./patterns.csv') as f:
    patterns = [(rule_name, parse_ports(port_list), re.compile(pattern)) for (rule_name, port_list, pattern) in
                (l.split(';') for l in f.read().splitlines())]

with open('./matches.txt') as f:
    matches = [l.split(': ') for l in f.read().splitlines()]

with open('./by_inst', errors='ignore') as f:
    ranks = {pkg: int(rank) for rank, pkg in
             (l.split()[:2] for l in f.read().splitlines() if not l.startswith('#') and not l.startswith('-'))}

with open('./versions.txt') as f:
    versions = {pkg: version for pkg, version in (l.split('=', maxsplit=1) for l in f.read().splitlines())}

packages = dict()
for match in matches:
    pkg = match[0]
    if pkg not in packages:
        rank = ranks.get(match[0], 9999999)
        version = versions.get(pkg, None)
        packages[pkg] = {'version': version, 'rank': rank, 'binaries': {}}
    pkg_dict = packages[pkg]

    binary = match[1]
    if binary not in pkg_dict['binaries']:
        pkg_dict['binaries'][binary] = list()
    ports = set(pkg_dict['binaries'][binary])

    for pattern in patterns:
        if pattern[2].fullmatch(match[1]):
            pattern_ports = pattern[1]
            ports.update(pattern_ports)

    pkg_dict['binaries'][binary] = sorted(ports)

with open('package_matches.json', 'w') as f:
    json.dump(packages, f)
