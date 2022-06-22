#!/bin/sh
# AmpFuzz pre-fuzz config script
# Use this script to create/modify
# config files for the fuzz target
sed -i 's/^agentaddress.*$/agentaddress\t127.0.0.1/g' /etc/snmp/snmpd.conf
