/*
 * BigBro @2023
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
MODULE_DESCRIPTION("Livepatch: troubleshooting for bpf/xdp");

static int replace;
module_param(replace, int, 0644);
MODULE_PARM_DESC(replace, "replace (default=0)");

#include "get_kallsyms_lookup_name.c"

static void (*pbq_enqueue)(struct bpf_cpu_map_entry *rcpu, struct xdp_frame *xdpf);

#define CPU_MAP_BULK_SIZE 8  /* 8 == one cacheline on 64-bit archs */
struct bpf_cpu_map_entry;

static int livepatch_cpu_map_enqueue(struct bpf_cpu_map_entry *rcpu, struct xdp_buff *xdp, struct net_device *dev_rx)
{
	struct xdp_frame *xdpf;

	xdpf = xdp_convert_buff_to_frame(xdp);
	if (unlikely(!xdpf)) {
		int metasize, headroom;

		headroom = xdp->data - xdp->data_hard_start;
		metasize = xdp->data - xdp->data_meta;

		printk("type: %d, headroom/metasize: %d/%d, size of struct xdp_frame: %ld\n", xdp->rxq->mem.type, headroom, metasize, sizeof(struct xdp_frame));

		return -EOVERFLOW;
	}

	/* Info needed when constructing SKB on remote CPU */
	xdpf->dev_rx = dev_rx;

	pbq_enqueue(rcpu, xdpf);
	return 0;
}

static struct klp_func funcs[] = {
	{
		.old_name = "cpu_map_enqueue",
		.new_func = livepatch_cpu_map_enqueue,
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

static int livepatch_bpf_map_redirect_init(void)
{
	int ret;
	kallsyms_lookup_name_type pkallsyms_lookup_name;

	ret = get_kallsyms_lookup_name(&pkallsyms_lookup_name);
	if (ret) {
		printk("Can't get kallsyms_lookup_name symbol (ret = %d).\n", ret);
		return -1;
	}

	pbq_enqueue = (typeof(pbq_enqueue))pkallsyms_lookup_name("bq_enqueue");
	if (!pbq_enqueue) {
		printk("Can't get bq_enqueue symbol.\n");
		return -1;
	}

	my_patch.replace = replace;
	ret = klp_enable_patch(&my_patch);
	if (ret)
		return -1;

	printk("livepatch: bpf_map_redirect loaded\n");

	return 0;
}

/*
 * In order to remove the ko module
 * 	1. echo 0 > /sys/kernel/livepatch/livepatch_bpf_map_redirect/enabled
 *	2. rmmod livepatch
 */
static void livepatch_bpf_map_redirect_exit(void)
{
	printk("livepatch: bpf_map_redirect unloaded\n");
}

module_init(livepatch_bpf_map_redirect_init);
module_exit(livepatch_bpf_map_redirect_exit);
#else
MODULE_LICENSE("GPL");
#endif
