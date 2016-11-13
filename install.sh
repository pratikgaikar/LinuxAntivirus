make clean
make 
rmmod antivirus.ko
insmod antivirus.ko
dmesg  -c
