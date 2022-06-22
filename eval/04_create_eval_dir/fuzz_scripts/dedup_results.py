#!/usr/bin/env python3

"""
This script is meant to be run inside the final config-container,
with a special bind-mount /fuzz_run that contains fuzz-results

The script will search this mount for inputs, and run each one against the track-instrumented version to obtain a tracking result with a generous 60 second timeout
"""

import glob
import json
import os
import subprocess
import socket
import time
import hashlib


def run_track(program, port, input_file, startup_timeout=5, response_timeout=60):
    with open(input_file, 'rb') as f:
        d = f.read()
    input_hash = hashlib.md5(d).hexdigest()
    output_file = f'track_{input_hash}'
    if os.path.exists(output_file):
        print(f'[WARN] Removing old track_file {output_file}')
        os.unlink(output_file)
    env = os.environ
    env.update({
        'ANGORA_TRACK_PATH': output_file,
        'ANGORA_EARLY_TERMINATION': 'None'
    })
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    p = subprocess.Popen(program, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(startup_timeout)
    s.sendto(d, ('127.0.0.1', port))
    time.sleep(response_timeout)
    p.terminate()
    try:
        p.communicate(timeout=response_timeout)
    except subprocess.TimeoutExpired:
        p.kill()
    s.close()
    return output_file


def get_todo():
    all_inputs = list(glob.glob('/fuzz_run/queue/id:*'))
    all_amps = list(glob.glob('/fuzz_run/amps/amp_*'))

    # exact choice per path_hash does not matter: two inputs with the same path_hash *should* have the same exact trace
    # tie break: take smallest input with best amp
    best_amp = dict()
    amp_hashes = dict()
    selected_amps = dict()
    for x in all_amps:
        factor, path_hash, content_hash = x.rsplit('_', maxsplit=3)[-3:]
        with open(x, 'rb') as f:
            d = f.read()
        length = len(d)
        factor = float(factor)
        if factor not in best_amp or factor < best_amp[path_hash] or (
                factor == best_amp[path_hash] and (path_hash not in selected_amps or d < selected_amps[path_hash][0])):
            best_amp[path_hash] = factor
            selected_amps[path_hash] = (d, x)
        amp_hashes[x] = content_hash
    amp_hashes_inv = {v: k for k, v in amp_hashes.items()}

    input_hashes = dict()
    for input_file in all_inputs:
        with open(input_file, 'rb') as f:
            d = f.read()
        input_hashes[input_file] = hashlib.md5(d).hexdigest()
    non_amp_inputs = [x for x in all_inputs if input_hashes[x] not in amp_hashes_inv]

    todo = non_amp_inputs + [p for d, p in selected_amps.values()]
    return todo


def get_prog_port():
    with open('/fuzz.sh') as f:
        fuzz_script = f.read()
    last_line = next(x for x in (x.lstrip() for x in fuzz_script.splitlines()[::-1]) if x.startswith('python'))
    script, args = last_line.split(' -- ')
    args = args.split()

    fuzz_args, prg, port = script.rsplit(maxsplit=2)
    prg = prg.strip('"')
    port = int(port.strip('"'))

    is_inetd = '--inetd' in fuzz_args
    if is_inetd:
        subprocess.run(['/02_fuzzer/harnesses/inetd/wrap.sh', str(port), prg])
        prg = f'{prg}.wrap.{port}.track'
    else:
        prg = f'{prg}.track'

    return [prg] + args, port


def to_json(track_file):
    p = subprocess.run(['/02_fuzzer/parse_track_file', track_file], capture_output=True)
    return json.loads(p.stdout or '[]')


def main():
    os.makedirs("/dedup_results")
    os.chdir("/dedup_results")

    program, port = get_prog_port()
    todo = get_todo()
    for x in todo:
        track_file = run_track(program, port, x)
        track_json = to_json(track_file)
        with open(track_file + '.json', 'w') as f:
            json.dump(track_json, f)


if __name__ == '__main__':
    main()
