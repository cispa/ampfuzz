#!/bin/sh
# AmpFuzz pre-fuzz config script
# Use this script to create/modify
# config files for the fuzz target
sed -i 's/^#\(.*imudp\)/\1/g' /etc/rsyslog.conf
