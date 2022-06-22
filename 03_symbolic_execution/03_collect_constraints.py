#!/usr/bin/env python3
import glob
import json
import logging
import os
import os.path
import argparse
import subprocess
import shutil

import socket
import sys
from os import walk
from time import sleep
import posix_ipc

# get the of location of script
ampfuzz_bin = os.path.dirname(os.path.realpath(__file__))

ampfuzz_var = '/var/ampfuzz'

# get the environment ready
my_env = os.environ.copy()
my_env['DEBIAN_FRONTEND'] = 'noninteractive'
my_env['CC'] = '/usr/bin/clang-11'
my_env['CXX'] = 'usr/bin/clang++-11'
my_env['PATH'] = '/usr/lib/llvm-11/bin:/usr/bin/zsh:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'


def dparser():
    par = argparse.ArgumentParser(
        description='sym_target expects a debian package name binary name together with path using debian as root, '
                    'examples are in ranked_packages.json')
    par.add_argument('binary', type=str,
                     help='Binary name and path')
    par.add_argument('port', type=int, default=53,
                     help='Port in use')
    par.add_argument('-i', '--inetd', action='store_true', help='Wrap with inetd harness')
    par.add_argument('args', type=str, nargs='*')
    return par


def exec_command(name, options, input=None, asuser=None):
    command = []
    if asuser is not None:
        command.append('sudo')
        command.append('-E')
        command.append('-u')
        command.append(asuser)
        command.append('--')
    command.append(name)
    command.extend(options)
    if input is not None:
        command.append(input)

    print(command)

    subprocess.check_call(command,
                          stdin=sys.stdin.fileno(),
                          stdout=sys.stdout.fileno(),
                          stderr=sys.stderr.fileno(),
                          env=my_env)


def par_exec_command(name, options, input=None, asuser=None, stdin=None, stdout=None, stderr=None, extra_env=None):
    command = []
    if asuser is not None:
        command.append('sudo')
        command.append('-E')
        command.append('-u')
        command.append(asuser)
        command.append('--')
    command.append(name)
    command.extend(options)
    if input is not None:
        command.append(input)

    run_env = my_env

    if extra_env:
        run_env = run_env.copy()
        run_env.update(extra_env)

    print(command)
    stdin = stdin or sys.stdin.fileno()
    stdout = stdout or sys.stdout.fileno()
    stderr = stderr or sys.stderr.fileno()

    p = subprocess.Popen(command, stdin=stdin, stdout=stdout, stderr=stderr, env=run_env)
    return p


def sym(executable, ports, args, inetd=False):
    out = executable + '.sym.result'
    timeout_start = 60
    if 'EX_TIMEOUT' in os.environ:
        timeout_reply = int(os.environ['EX_TIMEOUT'])
    else:
        timeout_reply = 10
    timeout_terminate = 5
    port = int(ports[0])
    # finally - symbolically executing
    sym_ex = f"{executable}.sym"
    # wrap with inetd?
    if inetd:
        exec_command(ampfuzz_bin + '/harnesses/inetd/wrap.sh', [str(port), sym_ex])
        sym_ex = f"{sym_ex}.wrap.{port}"

    amps_dir = '/amps'
    out_dir = '/sym_amps'

    os.makedirs(out_dir, exist_ok=True)

    # files are named amp_<factor>_<path_id>_<content_hash>,
    # use this to find the best amp per path with factor>=1
    amp_files = {}
    for amp in glob.glob(f'{amps_dir}/amp_*'):
        factor, path = amp.split('_')[1:3]
        factor = float(factor)
        if factor < 1.0:
            continue
        if path not in amp_files or amp_files[path][0] < factor:
            amp_files[path] = (factor, amp)

    checked_inputs = set()

    # collect path constraints for all amps, going from best to worst
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout_reply)
    for _, amp in sorted(amp_files.values(), reverse=True):
        content_hash = amp.split('_')[-1]
        if content_hash in checked_inputs:
            continue
        with open(out, 'ab') as sym_out, open(os.path.join(amps_dir, amp), 'rb') as amp_in, open(
                os.path.join(out_dir, os.path.basename(amp) + '.out.json'), 'w') as amp_out:
            responses = []
            listen_sem = posix_ipc.Semaphore(f"/sem_{os.path.basename(amp)}", posix_ipc.O_CREAT)
            p = par_exec_command(sym_ex, args, stderr=sym_out, extra_env={'SYMCC_LISTEN_SEM': listen_sem.name})
            try:
                listen_sem.acquire(timeout_start)  # allow some start-up time
                payload = amp_in.read()
                sock.sendto(payload, ('127.0.0.1', port))
                while True:
                    try:
                        responses.append(sock.recv(8192).hex())
                    except socket.timeout:
                        break
                json.dump(responses, amp_out)
                checked_inputs.add(content_hash)
            except posix_ipc.BusyError:
                # target failed to listen?
                logging.warning(f"Target {sym_ex} failed to open a listening socket, skipping {amp}")

            p.terminate()
            try:
                p.wait(timeout_terminate)
            except subprocess.TimeoutExpired:
                p.kill()
            listen_sem.unlink()


def main():
    # from IPython import embed; embed()
    # get the arg
    parser = dparser()
    args = parser.parse_args()
    executable = args.binary
    fuzzee_args = args.args

    ports = [args.port]

    # sym?
    sym(executable, ports, fuzzee_args, inetd=args.inetd)


if __name__ == '__main__':
    main()
