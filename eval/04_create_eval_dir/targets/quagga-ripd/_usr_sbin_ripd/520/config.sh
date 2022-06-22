#!/bin/sh
# AmpFuzz pre-fuzz config script
# Use this script to create/modify
# config files for the fuzz target
mkdir -p /run/quagga
chmod 777 /run/quagga
mkdir -p /etc/quagga/
touch /etc/quagga/ripd.conf
echo "! -*- rip -*-
!
! RIPd sample configuration file
!
! $Id: ripd.conf.sample,v 1.1 2002/12/13 20:15:30 paul Exp $
!
hostname ripd
password zebra
!
! debug rip events
! debug rip packet
!
router rip
! network 127.0.0.1/8
! route 127.0.0.1/8
!
! 
!log file ripd.log
!
log stdout" >> /etc/quagga/ripd.conf

