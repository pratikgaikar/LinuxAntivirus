#!/bin/bash
dir=`uname -r`
pwd=`echo linux-headers-${dir}`
gcc /usr/src/${pwd}/LinuxAntivirus/antivirus_check.c -o /usr/bin/antivirus_scan
gcc /usr/src/${pwd}/LinuxAntivirus/user.c -o /usr/bin/user
nohup sh /usr/src/${pwd}/LinuxAntivirus/scripts/run_user.sh &
cd /usr/src/${pwd}/LinuxAntivirus
sh install.sh
