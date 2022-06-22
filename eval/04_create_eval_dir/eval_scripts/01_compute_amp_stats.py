#!/usr/bin/env python3
# coding: utf-8

import os
import glob
import json
import gzip
import csv
import re
import glob
import json
from functools import total_ordering
from datetime import timedelta

import numpy as np

csv.field_size_limit(1 << 62)

UDP_HEADER_SIZE = 8
IP_HEADER_SIZE = 20
ETH_HEADER_SIZE = 6 + 6 + 2 + 4
MIN_ETH_FRAME_SIZE = 64


class PktSum:
    def __init__(self, l7_pkts):
        self._l7_raw = tuple(l7_pkts)

    @property
    def l7_pkts(self):
        return tuple(self._l7_raw)

    @property
    def l4_pkts(self):
        return tuple(x + UDP_HEADER_SIZE for x in self.l7_pkts)

    @property
    def l3_pkts(self):
        return tuple(x + IP_HEADER_SIZE for x in self.l4_pkts)

    @property
    def l2_pkts(self):
        return tuple(max(MIN_ETH_FRAME_SIZE, x + ETH_HEADER_SIZE) for x in self.l3_pkts)

    @property
    def l7_size(self):
        return sum(self.l7_pkts)

    @property
    def l4_size(self):
        return sum(self.l4_pkts)

    @property
    def l3_size(self):
        return sum(self.l3_pkts)

    @property
    def l2_size(self):
        return sum(self.l2_pkts)


@total_ordering
class Amp:
    def __init__(self, l7_in, l7_out):
        self._in = PktSum(l7_in)
        self._out = PktSum(l7_out)

    @property
    def l7_baf(self):
        return self._out.l7_size / self._in.l7_size

    @property
    def l4_baf(self):
        return self._out.l4_size / self._in.l4_size

    @property
    def l3_baf(self):
        return self._out.l3_size / self._in.l3_size

    @property
    def l2_baf(self):
        return self._out.l2_size / self._in.l2_size

    def __eq__(self, other):
        return (
                self._in.l7_pkts == other._in.l7_pkts
                and self._out.l7_pkts == other._out.l7_pkts
        )

    def __lt__(self, other):
        if other is None:
            return False
        cmp_a, cmp_b = (
            self._out.l2_size * other._in.l2_size,
            other._out.l2_size * self._in.l2_size,
        )
        if cmp_a == cmp_b:
            cmp_a, cmp_b = (
                self._out.l3_size * other._in.l3_size,
                other._out.l3_size * self._in.l3_size,
            )
        if cmp_a == cmp_b:
            cmp_a, cmp_b = (
                self._out.l4_size * other._in.l4_size,
                other._out.l4_size * self._in.l4_size,
            )
        if cmp_a == cmp_b:
            cmp_a, cmp_b = (
                self._out.l7_size * other._in.l7_size,
                other._out.l7_size * self._in.l7_size,
            )
        return cmp_a < cmp_b

    def __repr__(self):
        return f"Amp({self.l2_baf:.3f})"


def load_trace(trace_file):
    with open(trace_file) as f:
        trace_content = json.load(f)

    COND_LEN_OP = 0x8003

    # remove conditions that are unlabeled (unless they are length-conditions)
    filtered_conds = [
        c["base"]
        for c in trace_content
        if "base" in c
           and (c["base"]["lb1"] or c["base"]["lb2"] or c["base"]["op"] == COND_LEN_OP)
    ]

    return frozenset(
        (c["cmpid"], c["order"] >> 16, c["condition"]) for c in filtered_conds
    )


def get_hash(trace_file):
    match = re.search(r"track_(?P<hash>[0-9a-fA-F]{32}).json", trace_file)
    if match:
        return match.group("hash")
    else:
        raise ValueError("Err, tracefile does not specify hash")


class AmpStats:
    def __init__(self, load_dir):
        self.load_dir = load_dir
        self._path_hashes = self._load_path_hashes()
        self._path_amps, self._path_amp_info = self._load_path_amps()
        self._trace_max_amps = self._compute_max_amps()

    def _load_path_amps(self):
        cache_path = os.path.join(self.load_dir, ".path_amps.json")
        if os.path.exists(cache_path):
            with open(cache_path) as f:
                path_amp_info = json.load(f)
        else:
            with open(os.path.join(self.load_dir, "angora.log")) as log_file:
                first_line = None
                last_line = None
                second_last_line = None
                for line in log_file:
                    if first_line is None:
                        first_line = line
                    second_last_line = last_line
                    last_line = line
            try:
                rd = csv.DictReader(iter([first_line, last_line]))
                path_amp_info = next(rd)
                path_amp_info['amps'] = json.loads(path_amp_info['amps'])
            except:
                rd = csv.DictReader(iter([first_line, second_last_line]))
                path_amp_info = next(rd)
                path_amp_info['amps'] = json.loads(path_amp_info['amps'])
            with open(cache_path, 'w') as f:
                json.dump(path_amp_info, f)
        path_amps = {x["path"]: Amp(x["bytes_in"], x["bytes_out"]) for x in path_amp_info['amps']}
        return path_amps, path_amp_info

    def _load_path_hashes(self):
        cache_path = os.path.join(self.load_dir, ".path_hashes.json")
        if os.path.exists(cache_path):
            with open(cache_path) as f:
                path_hashes = json.load(f)
        else:
            path_hashes = dict()
            for amp_file in glob.glob(os.path.join(self.load_dir, "amps/amp_*")):
                match = re.search(r"_(?P<path_hash>[0-9a-fA-F]{16})_(?P<content_hash>[0-9a-fA-F]{32})", amp_file)
                if match:
                    path_hash_list = path_hashes.setdefault(match.group("content_hash"), [])
                    path_hash_list.append(match.group("path_hash"))
            with open(cache_path, 'w') as f:
                json.dump(path_hashes, f)
        return path_hashes

    def _get_path_hashes(self, content_hash):
        return self._path_hashes.get(content_hash, [])

    def _get_max_amp(self, path_hashes):
        return max(
            ((self._path_amps.get(path_hash), path_hash) for path_hash in path_hashes),
            default=(None, None),
        )

    def _load_max_amp(self, amp, path_hash):
        # sort in reverse -> best amps should come first, since amp-factor is second part of filename
        for amp_file in sorted(glob.glob(os.path.join(self.load_dir, f'amps/amp_*_{path_hash}_*')), reverse=True):
            with open(amp_file, 'rb') as f:
                amp_input = f.read()
            if len(amp_input) == amp._in.l7_size:
                return amp_input
        return None

    def _compute_max_amps(self):
        cache_path = os.path.join(self.load_dir, ".max_amps.json")
        if os.path.exists(cache_path):
            with open(cache_path) as f:
                trace_max_amps_info = json.load(f)
            trace_max_amps = {
                frozenset(tuple(x) for x in a["trace"]): {'amp': Amp(a["amp"]["bytes_in"], a["amp"]["bytes_out"]),
                                                          'path': a["path"], 'input': bytes.fromhex(a["input"])} for a
                in trace_max_amps_info}
        else:
            trace_max_amps = {}
            for trace_file in glob.glob(os.path.join(self.load_dir, "./dedup_results/track_*json")):
                trace = load_trace(trace_file)
                max_amp, path = self._get_max_amp(self._get_path_hashes(get_hash(trace_file)))
                if max_amp and (trace not in trace_max_amps or max_amp > trace_max_amps[trace]['amp']):
                    trace_max_amps[trace] = {'amp': max_amp, 'path': path}

            for v in trace_max_amps.values():
                v['input'] = self._load_max_amp(v['amp'], v['path'])

            with open(cache_path, 'w') as f:
                json.dump([{"trace": list(k),
                            "amp": {"bytes_in": list(v['amp']._in._l7_raw), "bytes_out": list(v['amp']._out._l7_raw)},
                            "path": v['path'], "input": v['input'].hex()} for k, v in trace_max_amps.items()], f)
        return trace_max_amps

    @property
    def n_execs(self):
        """
        Total number of target executions
        """
        return int(self._path_amp_info["execs"])

    @property
    def n_inputs(self):
        """
        Total number of inputs that produced new coverage *or* better amplifications
        """
        return int(self._path_amp_info["inputs"]) + int(self._path_amp_info["amp_inputs"])

    @property
    def n_resp_inputs(self):
        """
        Total number of inputs that produced new coverage *or* better amplifications *and* a response
        """
        return int(self._path_amp_info["amp_inputs"])

    @property
    def n_paths(self):
        """
        Total number of unique bitmaps
        """
        return int(self._path_amp_info["paths"])

    @property
    def n_resp_paths(self):
        """
        Total number of unique bitmaps with a response packet
        """
        return int(self._path_amp_info["amp_paths"])

    @property
    def n_msg_types(self):
        """
        Number of *unique* normalized traces for responses
        """
        return len(self._trace_max_amps)

    @property
    def n_amp_types(self):
        """
        Number of *unique* normalized traces leading to *amplifying* responses
        """
        return sum(1 for v in self._trace_max_amps.values() if v['amp'].l2_baf > 1.0)

    @property
    def max_amp(self):
        return max((v['amp'] for v in self._trace_max_amps.values()), default=None)


def load_conf(config_path):
    with open(config_path) as f:
        config = json.load(f)
    timeout = parse_timeout(config.get("timeout"))
    args = parse_args(config.get("args"))
    return {**args, "timeout": timeout, "package": config.get("pkg"), "program": config.get("target"),
            "port": int(config.get("port"))}


def parse_timeout(timeout_str):
    timeout_re = re.compile(
        r"((?P<hours>\d+)h)?((?P<minutes>\d+)m)?((?P<seconds>\d+)s)?"
    )
    match = timeout_re.match(timeout_str)
    if not match:
        return None
    return timedelta(
        **{k: int(v) for k, v in match.groupdict().items() if v}
    ).total_seconds()


def parse_args(args_str):
    args = {
        "startup_time_limit": 500000,
        "response_time_limit": 500000,
        "disable_listen_ready": False,
        "early_termination": "full",
        "disable_amp_mutation": False,
    }
    for tok in args_str.split():
        if not tok.strip().startswith("-a="):
            continue
        tok = tok.split("=", maxsplit=1)[1].strip().lstrip("-")
        if "=" in tok:
            k, v = tok.split("=", maxsplit=1)
            try:
                v = int(v)
            except ValueError:
                pass
            args[k] = v
        else:
            args[tok] = True
    return args


def analyze(result_dir):
    results = []

    for root, dirs, files in os.walk(result_dir):
        if "fuzz.cfg" not in files:
            continue

        conf = load_conf(os.path.join(root, "fuzz.cfg"))

        print(f"Checking {root}...")
        info = {**conf}
        if "angora.log" in files:
            a = AmpStats(root)

            info['n_execs'] = a.n_execs
            info['n_inputs'] = a.n_inputs
            info['n_resp_inputs'] = a.n_resp_inputs
            info['n_paths'] = a.n_paths
            info['n_resp_paths'] = a.n_resp_paths
            info['n_msg_types'] = a.n_msg_types
            info['n_amp_types'] = a.n_amp_types
            info['max_amp_l2'] = a.max_amp.l2_baf if a.max_amp else None
            info['max_amp_l7'] = (a.max_amp.l7_baf if a.max_amp._in.l7_size > 0 else np.inf) if a.max_amp else None
        else:
            info['n_msg_types'] = None
            info['n_amp_types'] = None
            info['max_amp_l2'] = None
            info['max_amp_l7'] = None

        print(info)
        results.append(info)

    with open(os.path.join(result_dir, 'results.json'), 'w') as f:
        json.dump(results, f)


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('dir', nargs='?', default='results', help='Result directory to analyze')
    args = parser.parse_args()

    analyze(args.dir)


if __name__ == '__main__':
    main()
