#!/bin/sh
# AmpFuzz pre-fuzz config script
# Use this script to create/modify
# config files for the fuzz target
echo "time	dgram	udp	wait	root	internal" >> /etc/inetd.conf
