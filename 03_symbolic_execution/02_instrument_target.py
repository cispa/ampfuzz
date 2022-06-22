#!/usr/bin/env python3
import os
import os.path
import argparse
import subprocess
import shutil
import sys

# get the of location of script
ampfuzz_bin = os.path.dirname(os.path.realpath(__file__))
make_sym = os.path.join(ampfuzz_bin, 'symcc_amp', 'make_sym')
ampfuzz_var = '/var/ampfuzz'


def dparser():
    par = argparse.ArgumentParser(
        description='fuzz_package expects a debian package name binary name together with path using debian as root, examples are in ranked_packages.json')
    par.add_argument('binary', type=str,
                     help='Binary name and path')
    par.add_argument('args', type=str, nargs='*')
    return par


def exec_command(name, options, input=None, asuser=None, allow_fail=False):
    command = []
    cmd_env = os.environ
    if asuser is not None:
        command.append('sudo')
        command.append('-E')
        command.append('-u')
        command.append(asuser)
        command.append('--')
        cmd_env = cmd_env.copy()
        cmd_env['HOME'] = os.path.expanduser(f'~{asuser}')
    command.append(name)
    command.extend(options)
    if input is not None:
        command.append(input)

    print(command)

    try:
        subprocess.check_call(command,
                              stdin=sys.stdin.fileno(),
                              stdout=sys.stdout.fileno(),
                              stderr=sys.stderr.fileno(),
                              env=cmd_env)
    except subprocess.CalledProcessError as e:
        if not allow_fail:
            raise e


def prepare_fuzzing(executable):
    exec_command(make_sym, [], executable)
    target_abi_file = f"{executable}.abilist.txt"
    shared_libs = subprocess.check_output(
        "cat /etc/apt/sources.list.d/*|grep -Po '(?<=file://)/var/ampfuzz/\S*'|xargs -I{} find {} -maxdepth 1 -name Packages|xargs cat |grep -Po '(?<=^Package: ).*$'|xargs -r dpkg -L 2>/dev/null|grep '\.so\>'|xargs -r readlink -f|sort -u",
        shell=True).decode().splitlines()
    for shared_lib in shared_libs:
        exec_command(make_sym, ['-l', '-a', target_abi_file], shared_lib, allow_fail=True)

    if os.path.exists(executable + '.orig') and os.path.isfile(executable + '.orig'):
        os.remove(executable + '.orig')
    in_dir = executable + '.in'
    out_dir = executable + '.out'
    if os.path.exists(out_dir) and os.path.isdir(out_dir):
        shutil.rmtree(out_dir)
    if not (os.path.exists(in_dir) and os.path.isdir(in_dir)):
        os.makedirs(in_dir)
    input_zero = os.path.join(in_dir, '00')
    if not os.path.exists(input_zero):
        with open(input_zero, 'wb') as f:
            f.write(b'a')


def main():
    # from IPython import embed; embed()
    # get the arg
    parser = dparser()
    args = parser.parse_args()
    executable = args.binary

    # prepare fuzzing
    prepare_fuzzing(executable)


if __name__ == '__main__':
    main()
