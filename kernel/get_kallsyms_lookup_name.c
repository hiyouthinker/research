/*
 * BigBro @2023
 */

static unsigned long (*pkallsyms_lookup_name)(const char *name) = NULL;

static int get_kallsyms_lookup_name(void)
{
	static struct kprobe kp = {
		.symbol_name = "kallsyms_lookup_name"
	};
	int ret = register_kprobe(&kp);

	if (ret)
		return ret;

	unregister_kprobe(&kp);

	pkallsyms_lookup_name = (typeof(pkallsyms_lookup_name))kp.addr;

	return 0;
}
