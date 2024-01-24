/*
 * BigBro @2023
 *
 * fix kernel bug
 * 		change 'return' to 'break'
 *		see https://elixir.bootlin.com/linux/v6.2.6/source/kernel/bpf/cpumap.c#L196
 */

#include <linux/module.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/kernel.h>
#include <linux/livepatch.h>
#include <linux/netdevice.h>
#include <linux/bpf.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,15,0)
MODULE_LICENSE("GPL");
MODULE_INFO(livepatch, "Y");
MODULE_AUTHOR("BigBro");
MODULE_DESCRIPTION("Livepatch: fix bug of cpumap for xdp generic mode");

static int replace;
module_param(replace, int, 0644);
MODULE_PARM_DESC(replace, "replace (default=0)");

#include "get_kallsyms_lookup_name.c"

static int (*pxdp_do_generic_redirect)(struct net_device *dev, struct sk_buff *skb,
			struct xdp_buff *xdp, struct bpf_prog *xdp_prog);
static u32 (*pbpf_prog_run_generic_xdp)(struct sk_buff *skb, struct xdp_buff *xdp,
			struct bpf_prog *xdp_prog);

/* Struct for every remote "destination" CPU in map */
struct bpf_cpu_map_entry {
	u32 cpu;	/* kthread CPU and map index */
	int map_id; /* Back reference to map */

	/* XDP can run multiple RX-ring queues, need __percpu enqueue store */
	struct xdp_bulk_queue __percpu *bulkq;

	struct bpf_cpu_map *cmap;

	/* Queue with potential multi-producers, and single-consumer kthread */
	struct ptr_ring *queue;
	struct task_struct *kthread;

	struct bpf_cpumap_val value;
	struct bpf_prog *prog;

	atomic_t refcnt; /* Control when this struct can be free'ed */
	struct rcu_head rcu;

	struct work_struct kthread_stop_wq;
};

static void livepatch_cpu_map_bpf_prog_run_skb(struct bpf_cpu_map_entry *rcpu,
					 struct list_head *listp,
					 struct xdp_cpumap_stats *stats)

{
	struct sk_buff *skb, *tmp;
	struct xdp_buff xdp;
	u32 act;
	int err;

	list_for_each_entry_safe(skb, tmp, listp, list) {
		act = pbpf_prog_run_generic_xdp(skb, &xdp, rcpu->prog);
		switch (act) {
		case XDP_PASS:
			break;
		case XDP_REDIRECT:
			skb_list_del_init(skb);
			err = pxdp_do_generic_redirect(skb->dev, skb, &xdp,
						      rcpu->prog);
			if (unlikely(err)) {
				kfree_skb(skb);
				stats->drop++;
			} else {
				stats->redirect++;
			}
			break;
		default:
			fallthrough;
		case XDP_ABORTED:
			fallthrough;
		case XDP_DROP:
			skb_list_del_init(skb);
			kfree_skb(skb);
			stats->drop++;
			break;
		}
	}
}

static struct klp_func funcs[] = {
	{
		.old_name = "cpu_map_bpf_prog_run_skb",
		.new_func = livepatch_cpu_map_bpf_prog_run_skb,
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
livepatch_bpf_cpumap_proc_show(struct seq_file *m, void *v)
{
	seq_printf(m, "old func: %pK, new func -> %pK\n", funcs[0].old_func, funcs[0].new_func);

	return 0;
}

static int
livepatch_bpf_cpumap_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, livepatch_bpf_cpumap_proc_show, NULL);
}

static ssize_t 
livepatch_bpf_cpumap_proc_write(struct file *file, const char __user *buffer,
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

static const struct proc_ops livepatch_bpf_lru_update_proc_ops = {
	.proc_open	= livepatch_bpf_cpumap_proc_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release = single_release,
	.proc_write	= livepatch_bpf_cpumap_proc_write,
};

static int livepatch_bpf_cpumap_init(void)
{
	int ret;
	struct proc_dir_entry *pde;
	kallsyms_lookup_name_type pkallsyms_lookup_name;

	ret = get_kallsyms_lookup_name(&pkallsyms_lookup_name);
	if (ret) {
		printk("Can't get kallsyms_lookup_name symbol (ret = %d).\n", ret);
		return -1;
	}

	pxdp_do_generic_redirect = (typeof(pxdp_do_generic_redirect))pkallsyms_lookup_name("xdp_do_generic_redirect");
	if (!pxdp_do_generic_redirect) {
		printk("Can't get xdp_do_generic_redirect symbol.\n");
		return -1;
	}

	pbpf_prog_run_generic_xdp = (typeof(pbpf_prog_run_generic_xdp))pkallsyms_lookup_name("bpf_prog_run_generic_xdp");
	if (!pbpf_prog_run_generic_xdp) {
		printk("Can't get bpf_prog_run_generic_xdp symbol.\n");
		return -1;
	}

	pde = proc_create("livepatch_bpf_cpumap", 0644, NULL, &livepatch_bpf_lru_update_proc_ops);
	if (!pde) {
		printk("Can't create /proc/livepatch_bpf_cpumap.\n");
		return -1;
	}

	my_patch.replace = replace;
	ret = klp_enable_patch(&my_patch);
	if (ret)
		goto remove_proc;

	return 0;
remove_proc:
	remove_proc_entry("livepatch_bpf_cpumap", NULL);
	return ret;
}

/*
 * In order to remove the ko module
 * 	1. echo 0 > /sys/kernel/livepatch/livepatch_bpf_cpumap/enabled
 *	2. rmmod livepatch
 */
static void livepatch_bpf_cpumap_exit(void)
{
	remove_proc_entry("livepatch_bpf_cpumap", NULL);
}

module_init(livepatch_bpf_cpumap_init);
module_exit(livepatch_bpf_cpumap_exit);
#else
MODULE_LICENSE("GPL");
#endif
