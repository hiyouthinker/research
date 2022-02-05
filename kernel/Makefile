obj-m := debug.o get_infos.o get_socket_info.o syscall_hijack.o
KDIR := /lib/modules/$(shell uname -r)/build
PWD:=$(shell pwd)
all:
	make -C $(KDIR) M=$(PWD) modules
clean:
	rm -fr *.ko *.o *.symvers *.order .*.o.cmd .*.ko.cmd *.cmd.o *.mod.c .cache.mk .tmp_versions
	#make -C $(KDIR) M=$(PWD) clean
