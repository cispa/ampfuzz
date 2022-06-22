#!/bin/sh
# AmpFuzz pre-fuzz config script
# Use this script to create/modify
# config files for the fuzz target
sed -i 's/\(disable\s*=\s*\)yes/\1no/g' /etc/xinetd.d/time* && sed -i 's/{$/{\n\tflags\t\t= IPv4/g' /etc/xinetd.d/time*
