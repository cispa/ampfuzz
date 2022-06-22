#!/usr/bin/env python3
import glob
import os
import os.path
import argparse
import subprocess
import shutil
import sys
from os import walk
from time import sleep
from honeypot_syn import gen_reply

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
        description='honeypot_syn expects a debian package name binary name together with path using debian as root, examples are in ranked_packages.json')
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


def par_exec_command(name, options, input=None, asuser=None, stdin=None, stdout=None, stderr=None):
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
    stdin = stdin or sys.stdin.fileno()
    stdout = stdout or sys.stdout.fileno()
    stderr = stderr or sys.stderr.fileno()

    p = subprocess.Popen(command, stdin=stdin, stdout=stdout, stderr=stderr, env=my_env)
    return p


def honeypot_syn_compare_replies():
    amps_dir = '/amps'
    # persistent_bytes has bytes that persistent when executing the real binary
    persistent_bytes = set()
    topmost = None
    size = 0
    syns = []
    # compare synthesized and real
    for amp in glob.glob(f'{amps_dir}/amp_*'):
        factor = float(amp.split('_')[-2])
        if factor < 1.0:
            continue
        with open(os.path.join(amps_dir, '_' + os.path.basename(amp) + '.syn.out'), 'rb') as syn_amp_out, open(
                os.path.join(amps_dir, '_' + os.path.basename(amp) + '.out'), 'rb') as amp_out:
                real = amp_out.read()
                if topmost is None:
                    topmost = real
                    size = len(topmost)
                else:
                    for i in range(0, size - 1):
                        if i < len(real):
                            if topmost[i] == real[i]:
                                persistent_bytes.add(i)
                            else:
                                persistent_bytes.discard(i)
                        else:
                            persistent_bytes.discard(i)
                syn = syn_amp_out.read()
                syns.append(syn)
    # syn_bytes_not_persistent has bytes that were persistent when executing the real binary but did change when executing the synthesized code
    syn_bytes_not_persistent = set()
    size = 0
    syns = []
    topmost = None
    for syn in syns:
        if topmost is None:
            topmost = syn
            size = len(syn)
        else:
            for i in range(0, size - 1):
                if i < len(syn):
                    if topmost[i] == syn[i]:
                        pass
                    else:
                        if i in persistent_bytes:
                            syn_bytes_not_persistent.add(i)
                else:
                    if i in persistent_bytes:
                        syn_bytes_not_persistent.add(i)
    with open('/real_syn_comp.out', 'w') as real_syn_comp:
        real_syn_comp.write("Persistent bytes:\n")
        p_bytes_str = ','.join(str(e) for e in persistent_bytes)
        real_syn_comp.write(p_bytes_str + '\n')
        if len(syn_bytes_not_persistent) == 0:
            real_syn_comp.write("Test pass: all persistent bytes are persistent in the synthesized output")
        else:
            n_p_bytes_str = ','.join(str(e) for e in syn_bytes_not_persistent)
            real_syn_comp.write("Test fail: some of the bytes that should be persistent were not in the synthesized output, they are " + n_p_bytes_str)


def honeypot_syn_get_replies(executable, ports, args, inetd=False):
    timeout_start = 2
    timeout_reply = 10
    time_between_syn_and_real = 2
    port = str(ports[0])
    # finally - testing honeypot synthesis
    sym_ex = f"{executable}.sym"
    # wrap with inetd?
    if inetd:
        exec_command(ampfuzz_bin + '/harnesses/inetd/wrap.sh', [port, executable])
        executable = f"{executable}.wrap.{port}"

    amps_dir = '/amps'

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

    # generating outputs with synthesized honeypot code
    # collect path constraints for all amps, going from best to worst
    for _, amp in sorted(amp_files.values(), reverse=True):
        with open(os.path.join(amps_dir, amp), 'rb') as amp_in, open(
                os.path.join(amps_dir, '_' + os.path.basename(amp) + '.syn.out'), 'wb') as syn_amp_out:
            input = amp_in.read()
            output = gen_reply(input)
            syn_amp_out.write(output)
    # generating outputs with real code
    for amp in glob.glob(f'{amps_dir}/amp_*'):
        factor = float(amp.split('_')[-2])
        if factor < 1.0:
            continue
        with open(os.path.join(amps_dir, amp), 'rb') as amp_in, open(
                os.path.join(amps_dir, '_' + os.path.basename(amp) + '.out'), 'wb') as amp_out:
            p = par_exec_command(executable, args)
            sleep(timeout_start)  # allow some start-up time
            par_exec_command('nc', ['-u', '127.0.0.1', port], stdin=amp_in, stdout=amp_out)
            sleep(timeout_reply)  # allow some computation time
            p.terminate()


def main():
    # from IPython import embed; embed()
    # get the arg
    parser = dparser()
    args = parser.parse_args()
    executable = args.binary
    fuzzee_args = args.args

    ports = [args.port]

    # test synthesized honeypot code?
    honeypot_syn_get_replies(executable, ports, fuzzee_args, inetd=args.inetd)
    honeypot_syn_compare_replies()

if __name__ == '__main__':
    main()