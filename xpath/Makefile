obj-m += xpath.o
xpath-y := params.o xpath_table.o flow_table.o net_util.o netlink.o netfilter.o main.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	gcc -o xpath-user user.c

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f xpath-user
