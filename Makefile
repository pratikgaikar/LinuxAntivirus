obj-m += antivirus.o 

antivirus-y := main.o linkedlist.o blacklist.o file_operation.o

INC=/lib/modules/$(shell uname -r)/build/arch/x86/include

all: clean antivirus

antivirus:
	        make -Wall -Werror -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	        make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
      
