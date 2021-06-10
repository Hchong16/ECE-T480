KDIR ?= /lib/modules/$(shell uname -r)/build

obj-m += fakedrive.o

all: test
	make -C $(KDIR) M=$(PWD) modules

test:
	gcc -o test test.c

clean:
	make -C $(KDIR) M=$(PWD) clean
	rm -f *.o test
