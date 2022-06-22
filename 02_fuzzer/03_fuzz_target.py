#!/usr/bin/env python3
import glob
import os
import os.path
import argparse
import subprocess
import shutil
import sys

# get the of location of script
ampfuzz_bin = os.path.dirname(os.path.realpath(__file__))
cc_bin = os.path.join(ampfuzz_bin, 'pre_clang')
cxx_bin = os.path.join(ampfuzz_bin, 'pre_clang++')

ampfuzz_var = '/var/ampfuzz'

# get the environment ready
my_env = os.environ.copy()
my_env['DEBIAN_FRONTEND'] = 'noninteractive'
my_env['CC'] = cc_bin
my_env['CXX'] = cxx_bin
my_env['LLVM_COMPILER'] = 'clang'
my_env['LLVM_CC_NAME'] = 'clang'
my_env['LLVM_CXX_NAME'] = 'clang++'
my_env['LLVM_CPP_NAME'] = 'clang-cpp'
my_env['LLVM_COMPILER_PATH'] = '/usr/lib/llvm-11/bin'
my_env['PATH'] = '/usr/lib/llvm-11/bin:/usr/bin/zsh:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'


def dparser():
    par = argparse.ArgumentParser(
        description='fuzz_target expects a debian package name binary name together with path using debian as root, examples are in ranked_packages.json')
    par.add_argument('binary', type=str,
                     help='Binary name and path')
    par.add_argument('port', type=int, help='Port in use')
    par.add_argument('-n', '--no-fuzz', action='store_true',
                     help='Don\'t actually fuzz, just prepare everything for it (helpful if e.g. you need to edit '
                          'another config file beforehand)')
    par.add_argument('-i', '--inetd', action='store_true', help='Wrap with inetd harness')
    par.add_argument('-a', '--arg', dest='args', action='append', help='Extra argument for fuzzer')
    par.add_argument('target_args', type=str, nargs='*', help='Arguments for target invocation')
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


def fuzz(executable, ports, args, dryrun=False, inetd=False, extra_args=None):
    if extra_args is None:
        extra_args = []
    in_dir = executable + '.in'
    out_dir = executable + '.out'
    targets = executable + '.targets.json'
    fast = executable + '.fast'
    track = executable + '.track'
    port = str(ports[0])
    # wrap with inetd?
    if inetd:
        exec_command(ampfuzz_bin + '/harnesses/inetd/wrap.sh', [port, executable])
        fast = f"{executable}.wrap.{port}.fast"
        track = f"{executable}.wrap.{port}.track"

    # finally - fuzzing
    full_args = extra_args + ['-c', targets, '-i', in_dir, '-o', out_dir, '-t', track, '--target_addr',
                              '127.0.0.1:' + port, '--', fast] + args
    if dryrun:
        print("Execute when ready:")
        print(' '.join([ampfuzz_bin + '/fuzzer'] + full_args))
    else:
        exec_command(ampfuzz_bin + '/fuzzer', full_args)


def main():
    # from IPython import embed; embed()
    # get the arg
    parser = dparser()
    args = parser.parse_args()

    # fuzz?
    fuzz(args.binary, [args.port], args.target_args, dryrun=args.no_fuzz, inetd=args.inetd, extra_args=args.args)


if __name__ == '__main__':
    main()
