/*
 * BigBro @2024
 */

#include <linux/version.h>
#include <linux/module.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,15,0)
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <net/net_namespace.h>

#include "get_kallsyms_lookup_name.c"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("BigBro");
MODULE_DESCRIPTION("show infos for ftrace");

#define one_byte(a) (a & 0xff)

static void *func;
static char symbol[64] = {"udp_rcv"};
static kallsyms_lookup_name_type pkallsyms_lookup_name;

static ssize_t ftrace_test_proc_write(struct file *file, const char __user *buffer,
		size_t count, loff_t *f_pos)
{
	char *p;

	if (count >= 64)
		return -E2BIG;

	memset(symbol, 0, sizeof(symbol));
	if (copy_from_user(symbol, buffer, count))
		return -EFAULT;

	p = strchr(symbol, '\n');
	if (p)
		*p = '\0';

	return count;
}

static int ftrace_test_proc_show(struct seq_file *m, void *v)
{
	func = (void *)pkallsyms_lookup_name(symbol);
	if (!func)
		return -EINVAL;

	seq_printf(m, "0x%02x 0x%02x 0x%02x 0x%02x 0x%02x @%s\n",
			one_byte(*((char *)func)), one_byte(*((char *)func + 1)),
			one_byte(*((char *)func + 2)), one_byte(*((char *)func + 3)),
			one_byte(*((char *)func + 4)), symbol);

	return 0;
}

static int ftrace_test_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, ftrace_test_proc_show, NULL);
}

static const struct proc_ops ftrace_test_proc_ops = {
	.proc_open	= ftrace_test_proc_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release = single_release,
	.proc_write	= ftrace_test_proc_write,
};

static int __init ftrace_test_init(void)
{
    struct proc_dir_entry *pde;
	int ret;
    
    ret = get_kallsyms_lookup_name(&pkallsyms_lookup_name);
	if (ret) {
		printk("Can't get kallsyms_lookup_name symbol (ret = %d).\n", ret);
		return -1;
	}

	pde = proc_create("ftrace_test", 0644, init_net.proc_net, &ftrace_test_proc_ops);
	if (!pde) {
		printk("Can't create ftrace_test.\n");
		goto err;
	}

	printk("ftrace_test module loaded successfully\n");
	return 0;
err:
	return -1;
}

static void __exit ftrace_test_cleanup(void)
{
	remove_proc_entry("ftrace_test", init_net.proc_net);

	printk("ftrace_test module unloaded successfully\n");
}

module_init(ftrace_test_init);
module_exit(ftrace_test_cleanup);
#else
MODULE_LICENSE("GPL");
#endif
