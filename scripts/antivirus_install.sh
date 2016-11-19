#!/bin/bash
gcc ../antivirus_check.c -o /usr/bin/antivirus_scan
gcc ../user.c -o /usr/bin/user
nohup run_user.sh &
sh ../install.sh
