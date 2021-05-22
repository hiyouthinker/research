/*
 * BigBro
 */

#include <linux/module.h>
#include <linux/timer.h>
#include <linux/delay.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <net/net_namespace.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("BigBro");
MODULE_DESCRIPTION("for debug");

static struct timer_list my_basic_timer;
EXPORT_SYMBOL(my_basic_timer);

static ssize_t 
my_debug_proc_write(struct file *file, const char __user *buffer,
		size_t count, loff_t *f_pos)
{
	char in[32] = {0};

	if (copy_from_user(in, buffer,
		count >= sizeof(in) ? sizeof(in) - 1 : count))
		return -EFAULT;

	if (in[0] == '1') {
		mod_timer(&my_basic_timer, jiffies + 5 * HZ);
	} else {
		del_timer(&my_basic_timer);
	}

	printk("%s: input: %s\n", __func__, in);
	return count;
}

static int
my_debug_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, NULL, NULL);
}

static const struct file_operations my_debug_proc_ops = {
	.owner	= THIS_MODULE,
	.open	= my_debug_proc_open,
	.read	= seq_read,
	.llseek	= seq_lseek,
	.release = single_release,
	.write	= my_debug_proc_write,
};

static void my_debug_timer_handler(struct timer_list *timer)
{
	int cpu = smp_processor_id();

	printk("%s: jiffies: %lu @CPU%d\n", __func__, jiffies, cpu);
//	mod_timer(&my_basic_timer, jiffies + 3 * HZ);
}

static int __init my_debug_init(void)
{
	timer_setup(&my_basic_timer, my_debug_timer_handler, 0);
	proc_create("xxxx", 0644, init_net.proc_net, &my_debug_proc_ops);
	printk("Hello\n");
	return 0;
}

static void __exit my_debug_cleanup(void)
{
	remove_proc_entry("xxxx", init_net.proc_net);
	printk("Bye\n");
}

module_init(my_debug_init);
module_exit(my_debug_cleanup);
