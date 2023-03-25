/*
 * BigBro @2023
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>

static unsigned long (*pkallsyms_lookup_name)(const char *name) = NULL;

int __init lookup_test_init(void)
{
	struct kprobe kp = {
		.symbol_name = "kallsyms_lookup_name"
	};

	if (register_kprobe(&kp) < 0)
		return -1;

	unregister_kprobe(&kp);

	printk("Found at 0x%px for kallsyms_lookup_name\n", kp.addr);
	
	pkallsyms_lookup_name = (typeof(pkallsyms_lookup_name))kp.addr;

	printk("ip_rcv: 0x%px!\n", (void *)pkallsyms_lookup_name("ip_rcv"));
	return 0;
}

void __exit lookup_test_cleanup(void)
{
	printk("bye!\n");
}

MODULE_LICENSE("GPL");

module_init(lookup_test_init);
module_exit(lookup_test_cleanup);
