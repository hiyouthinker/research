obj-m := kprobe_xdp_redirect.o kprobe_test.o get_system_stat.o get_map_info.o get_common_infos.o get_socket_info.o syscall_hijack.o print_skb.o kallsyms_lookup_name.o call_usermodehelper.o
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
EXTRA_CFLAGS += -I$(PWD)/include

all:
	make -C $(KDIR) M=$(PWD) modules EXTRA_CFLAGS+=$(EXTRA_CFLAGS)
clean:
	#rm -fr *.ko *.o *.symvers *.order *.order.cmd .*.o.cmd *.mod.cmd .*.ko.cmd *.cmd.o *.mod.c *.mod .cache.mk .tmp_versions
	make -C $(KDIR) M=$(PWD) clean
