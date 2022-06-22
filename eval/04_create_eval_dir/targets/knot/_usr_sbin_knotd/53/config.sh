#!/bin/sh
# AmpFuzz pre-fuzz config script
# Use this script to create/modify
# config files for the fuzz target
mkdir -p /run/knot && chown knot:knot /run/knot && chmod 775 /run/knot
sed -i 's/^server:/server:\n    udp-workers: 1\n    tcp-workers: 1\n    background-workers: 1/g' /etc/knot/knot.conf

