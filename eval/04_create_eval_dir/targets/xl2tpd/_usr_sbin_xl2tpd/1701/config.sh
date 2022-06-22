#!/bin/sh
# AmpFuzz pre-fuzz config script
# Use this script to create/modify
# config files for the fuzz target
mkdir -p /var/run/xl2tpd
mkfifo /var/run/xl2tpd/l2tp-control
