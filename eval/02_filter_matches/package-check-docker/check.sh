#!/usr/bin/bash
set -eux
export LC_ALL=C

TODO=/eval/todo

NO_START=/root/fake

ensure_nostart(){
	# see https://askubuntu.com/a/77530
	mkdir -p ${NO_START}
	while read prg
	do
		rm -f "${NO_START}/${prg}"
		ln -s /bin/true "${NO_START}/${prg}"
	done <<EOF
initctl
invoke-rc.d
restart
start
stop
start-stop-daemon
service
deb-systemd-helper
EOF
}

fix_debconf(){
	echo "resolvconf resolvconf/linkify-resolvconf boolean false" | debconf-set-selections
}

update_apt(){
	apt update -y > /dev/null 2>&1
}

install(){
	#echo "Installing $1..."
	PATH=${NO_START}:${PATH} apt install -y "$1" > /dev/null 2>&1
}

purge(){
	#echo "Removing $1..."
	apt purge -y "$1" > /dev/null 2>&1
}

is_legit(){
	#echo "Checking $1..."
	real=$(readlink -f "$1")
	#echo "Actual path of $1: ${real}"
	file "${real}" | grep -q "ELF"
}

check_package_binaries(){
	#echo "Locating binaries for $1"
	for bin_path in $(grep "$1:" ${TODO}|cut -d':' -f2|xargs|sort -u)
	do
		if is_legit "${bin_path}"
		then
			echo "$1: ${bin_path}"
		fi
	done
}

test_package(){
	install $1
	check_package_binaries $1
	purge $1
}

read_input(){
	cat |sort -u > ${TODO}
}

main(){
	fix_debconf
	update_apt
	ensure_nostart
	read_input
	for pkg in $(cut -d':' -f1 ${TODO}|sort -u)
	do
		test_package "${pkg}"
	done
}



# call it
main
