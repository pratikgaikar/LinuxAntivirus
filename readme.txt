README:

Installation & Testing:

The antivirus software can be installed only if the user has root privileges.  Antivirus scan can be executed by normal user.
Here are the steps to get the antivirus code and install antivirus:
1.	The module is installed on the VMWARE virtual machine with linux kernel version 4.2.0-27-generic. Run the following git clone command in the 		/usr/src/linux-headers-4.2.0-27-generic folder to clone the code present in the git repository LinuxAntivirus:
		git clone https://github.com/pratikgaikar/LinuxAntivirus.git 
		
2.	To install antivirus run the following script from the directory /usr/src/linux-headers-4.2.0-27-generic/LinuxAntivirus/scripts/:
		antivirus_install
		
3.	After the script is executed, the antivirus module is inserted into the kernel and scanning starts

4.	The on demand mode of antivirus scan can be executed using the following command:
		antivirus_scan testfiles/ 
		This would scan the whole of testfiles directory.
		antivirus_scan testfiles/testfile1
		This would scan only testfile1 of testfiles directory.
		antivirus_scan testfiles/   testfiles2/
		This would first scan testfiles directory, then scan testfiles2 directory.
		
5.	Every file which is opened or executed by the user is scanned for virus and appropriate action is taken.
		
6.	Run cat command to open a virus file - On Access mode
		cat testfiles/testfile1
		
7.	The module could also be tested by executing the following command within the /usr/src/linux-headers-4.2.0-27-generic/LinuxAntivirus/scripts/ folder by which all the open and execve related system calls are invoked
		./testprogram
		
8.	To update the whitelist and blacklist file, the following script is to be executed when the antivirus module is not inserted: 
		antivirus_update

