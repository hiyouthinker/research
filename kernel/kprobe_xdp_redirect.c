/*
 * BigBro @2023
 *
 * fix kernel bug
 * 		change 'return' to 'break'
 *		see https://elixir.bootlin.com/linux/v6.2.6/source/kernel/bpf/cpumap.c#L196
 */

#define pr_fmt(fmt) "%s: " fmt, __func__

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/netdevice.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,15,0)
#define MAX_SYMBOL_LEN	64
static char symbol[MAX_SYMBOL_LEN] = "cpu_map_bpf_prog_run_skb";

#include "get_kallsyms_lookup_name.c"

static int (*pxdp_do_generic_redirect)(struct net_device *dev, struct sk_buff *skb,
			struct xdp_buff *xdp, struct bpf_prog *xdp_prog);
static u32 (*pbpf_prog_run_generic_xdp)(struct sk_buff *skb, struct xdp_buff *xdp,
			struct bpf_prog *xdp_prog);

/* Struct for every remote "destination" CPU in map */
struct bpf_cpu_map_entry {
	u32 cpu;    /* kthread CPU and map index */
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

static int __kprobes handler_pre(struct kprobe *p, struct pt_regs *regs);
static void __kprobes handler_post(struct kprobe *p, struct pt_regs *regs, unsigned long flags);

static struct kprobe kp = {
	.symbol_name	 = symbol,
	.pre_handler = handler_pre,
	.post_handler = handler_post,
};

/* kprobe pre_handler: called just before the probed instruction is executed */
static int __kprobes handler_pre(struct kprobe *p, struct pt_regs *regs)
{
#ifdef CONFIG_X86
	/*
	 * first argument:  regs->di
	 * second argument: regs->si
	 * third argument:  regs->dx
	 * fourth argument: regs->cx
	 */
	struct bpf_cpu_map_entry *rcpu = (struct bpf_cpu_map_entry *)regs->di;
	struct list_head *listp = (struct list_head *)regs->si;
	struct xdp_cpumap_stats *stats = (struct xdp_cpumap_stats *)regs->dx;

	struct sk_buff *skb, *tmp;
	struct xdp_buff xdp;
	u32 act;
	int err;

	if (!rcpu || !listp || !stats) {
		pr_info("<%s> invalid argument\n", p->symbol_name);
		return 0;
	}

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
#else
#error("unsupported platform\n")
#endif
	return 0;
}

/* kprobe post_handler: called after the probed instruction is executed */
static void __kprobes handler_post(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
#ifdef CONFIG_X86
#endif
}

static int __init kprobe_init(void)
{
	int ret;
	kallsyms_lookup_name_type pkallsyms_lookup_name;

	ret = register_kprobe(&kp);
	if (ret < 0) {
		pr_err("register_kprobe failed, returned %d\n", ret);
		return ret;
	}

	ret = get_kallsyms_lookup_name(&pkallsyms_lookup_name);
	if (ret) {
		printk("Can't get kallsyms_lookup_name symbol (ret = %d).\n", ret);
		goto fail;
	}

	pxdp_do_generic_redirect = (typeof(pxdp_do_generic_redirect))pkallsyms_lookup_name("xdp_do_generic_redirect");
	if (!pxdp_do_generic_redirect) {
		printk("Can't get xdp_do_generic_redirect symbol.\n");
		goto fail;
	}

	pbpf_prog_run_generic_xdp = (typeof(pbpf_prog_run_generic_xdp))pkallsyms_lookup_name("bpf_prog_run_generic_xdp");
	if (!pbpf_prog_run_generic_xdp) {
		printk("Can't get bpf_prog_run_generic_xdp symbol.\n");
		goto fail;
	}

	pr_info("Planted kprobe at %pK\n", kp.addr);
	return 0;
fail:
	unregister_kprobe(&kp);
	return -1;
}

static void __exit kprobe_exit(void)
{
	unregister_kprobe(&kp);
	pr_info("kprobe at %p unregistered\n", kp.addr);
}

module_init(kprobe_init)
module_exit(kprobe_exit)
MODULE_LICENSE("GPL");
#else
MODULE_LICENSE("GPL");
#endif
