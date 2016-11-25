#!/bin/bash

files=$(find $1 -type d \( -path ./.git -o \
                  -path ./log -o \
                  -path ./public -o \
                  -path ./tmp \) -prune -o \
       ! -type d -print)
#echo $files
for file in $files
do
blacklist_sha1=`sha1sum $file`
#echo $blacklist_sha1
IFS=' ' read -ra blacklist_sha1Arr <<< "$blacklist_sha1"
echo ${blacklist_sha1Arr[0]} >>/tmp/sha1sum.txt
done
