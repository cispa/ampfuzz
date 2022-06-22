#!/bin/sh
# AmpFuzz pre-fuzz config script
# Use this script to create/modify
# config files for the fuzz target
sed -i 's/transport:/#transport:/g;s/\(totem {\)/\1\n\ttransport: udp/g' /etc/corosync/corosync.conf
