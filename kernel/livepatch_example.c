/*
 * BigBro @2023
 */

#include <linux/module.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/kernel.h>
#include <linux/livepatch.h>

MODULE_LICENSE("GPL");
MODULE_INFO(livepatch, "Y");
MODULE_AUTHOR("BigBro");
MODULE_DESCRIPTION("Livepatch test: atomic replace");

static int replace;
module_param(replace, int, 0644);
MODULE_PARM_DESC(replace, "replace (default=0)");

#include <linux/seq_file.h>
static int livepatch_meminfo_proc_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%s: %s\n", THIS_MODULE->name,
		   "this has been live patched");
	return 0;
}

static struct klp_func funcs[] = {
	{
		.old_name = "meminfo_proc_show",
		.new_func = livepatch_meminfo_proc_show,
	}, {}
};

static struct klp_object objs[] = {
	{
		/* name being NULL means vmlinux */
		.funcs = funcs,
	}, {}
};

static struct klp_patch my_patch = {
	.mod = THIS_MODULE,
	.objs = objs,
	/* set .replace in the init function below for demo purposes */
};

static int
livepatch_proc_show(struct seq_file *m, void *v)
{
	seq_printf(m, "old func: %pK, new func -> %pK\n", funcs[0].old_func, funcs[0].new_func);

	return 0;
}

static int
livepatch_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, livepatch_proc_show, NULL);
}

static ssize_t 
livepatch_proc_write(struct file *file, const char __user *buffer,
		size_t count, loff_t *f_pos)
{
	char cmd[32] = {0};
	char *p;

	if (copy_from_user(cmd, buffer,
		count >= sizeof(cmd) ? sizeof(cmd) - 1 : count))
		return -EFAULT;

	p = strchr(cmd, '\n');
	if (p)
		*p = '\0';

	printk("cmd: %s\n", cmd);

	return count;	
}

static const struct proc_ops livepatch_proc_ops = {
	.proc_open	= livepatch_proc_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release = single_release,
	.proc_write	= livepatch_proc_write,
};

static int test_klp_atomic_replace_init(void)
{
	struct proc_dir_entry *pde;

	pde = proc_create("livepatch", 0644, NULL, &livepatch_proc_ops);
	if (!pde) {
		printk("Can't create /proc/livepatch.\n");
		return -1;
	}

	my_patch.replace = replace;
	return klp_enable_patch(&my_patch);
}

/*
 * In order to remove the ko module
 * 	1. echo 0 > /sys/kernel/livepatch/livepatch/enabled
 *	2. rmmod livepatch
 */
static void test_klp_atomic_replace_exit(void)
{
	remove_proc_entry("livepatch", NULL);
}

module_init(test_klp_atomic_replace_init);
module_exit(test_klp_atomic_replace_exit);
