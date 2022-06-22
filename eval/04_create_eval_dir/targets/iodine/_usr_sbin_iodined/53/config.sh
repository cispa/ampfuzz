#!/bin/sh
# AmpFuzz pre-fuzz config script
# Use this script to create/modify
# config files for the fuzz target
mkdir -p /dev/net
mknod /dev/net/tun c 10 200

