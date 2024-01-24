/*
 * BigBro @2023
 */

#include <linux/kprobes.h>

typedef unsigned long (*kallsyms_lookup_name_type)(const char *name);

static int get_kallsyms_lookup_name(kallsyms_lookup_name_type *pfunc)
{
	struct kprobe kp = {
		.symbol_name = "kallsyms_lookup_name"
	};
	int ret = register_kprobe(&kp);

	if (ret)
		return ret;

	unregister_kprobe(&kp);

	*pfunc = (kallsyms_lookup_name_type)kp.addr;

	return 0;
}
