#!/usr/bin/env python3
import glob
import os
import os.path
import argparse
import re
import subprocess
import shutil
import sys
from datetime import datetime

# get the of location of script
ampfuzz_bin = os.path.dirname(os.path.realpath(__file__))
cc_bin = os.path.join(ampfuzz_bin, 'pre_clang')
cxx_bin = os.path.join(ampfuzz_bin, 'pre_clang++')
compiler_export_regex = re.compile(r'^export\s+(CC|CXX)\s*=.*')
changelog_version_regex = re.compile(r'^(?P<pkgname>.*) \((.*:)?(?P<upstream_version>.*)\) (?P<remainder>.*)$')
dpkg_parsechangelog = re.compile(r'(dpkg-parsechangelog)(\s+\|)')
ampfuzz_var = '/var/ampfuzz'

# get the environment ready
my_env = os.environ.copy()
my_env['DEBIAN_FRONTEND'] = 'noninteractive'
# parallel=n ? for DEB_BUILD_OPTIONS
my_env['DEB_BUILD_OPTIONS'] = 'nocheck'
my_env['CFLAGS'] = ' -I/usr/include/tirpc'
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
        description='fuzz_package expects a debian package name binary name together with path using debian as root, examples are in ranked_packages.json')
    par.add_argument('-v', '--version', type=str, help='Package version')
    par.add_argument('-f', '--force', action='store_true', help='Force rebuild')
    par.add_argument('name', type=str, help='Package name')
    return par


def symlink(link, target, backup=True):
    if backup and os.path.exists(link):
        exec_command('cp', [link, link + ".bak"])
    exec_command('ln', ['-sf', target, link], None)
    if os.path.realpath(link) == target:
        print("Success link for: " + link + "->" + target)
    else:
        print("Failure link for: " + link + "->" + target)


def unsymlink(link):
    if os.path.exists(link):
        exec_command('rm', [link])
    if os.path.exists(link + '.bak'):
        exec_command('mv', [link + ".bak", link])


def exec_command(name, options, input=None, asuser=None, allow_fail=False):
    command = []
    cmd_env = my_env
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

def install_local_repository(pkg_build_dir, package):
    repo_list = f"/etc/apt/sources.list.d/{package}.list"

    with open(repo_list, 'w') as f:
        f.write(f"deb [trusted=yes] file://{pkg_build_dir} /")

    # update from new local repository only
    exec_command("apt-get", ["update", "-o", f"Dir::Etc::sourcelist={repo_list}"])


def install(pkg_build_dir, package):
    install_local_repository(pkg_build_dir, package)

    # install package from our repository
    exec_command("apt-get", ["install", "-f", "-y"], package)
    # also install "updates" from our repository
    exec_command("apt-get", ["upgrade", "-f", "-y"])



def main():
    # from IPython import embed; embed()
    # get the arg
    parser = dparser()
    args = parser.parse_args()
    package = args.name
    version = args.version or None
    pkg_build_dir = os.path.join(ampfuzz_var, 'pkg_build', package)

    # install the package
    install(pkg_build_dir, package)


if __name__ == '__main__':
    main()
