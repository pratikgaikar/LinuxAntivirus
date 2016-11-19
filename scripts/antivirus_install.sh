#!/bin/bash
gcc ../antivirus_check.c -o /usr/bin/antivirus_scan
gcc ../user.c -o /usr/bin/user
nohup sh run_user.sh &
cd ../
sh install.sh
