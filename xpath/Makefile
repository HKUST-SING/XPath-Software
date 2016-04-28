obj-m += xpath.o
xpath-y := path.o flow.o network.o netfilter.o main.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
