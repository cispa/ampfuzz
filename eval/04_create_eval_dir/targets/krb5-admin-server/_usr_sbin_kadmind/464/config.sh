#!/bin/sh
# AmpFuzz pre-fuzz config script
# Use this script to create/modify
# config files for the fuzz target
kdb5_util create -s -r ATHENA.MIT.EDU -P ''
touch /etc/krb5kdc/kadm5.acl