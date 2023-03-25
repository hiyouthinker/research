/*
 * BigBro @2023
 */

#define pr_fmt(fmt) "%s: " fmt, __func__

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/netdevice.h>
#include <linux/filter.h>

#define MAX_SYMBOL_LEN	64
static char symbol[MAX_SYMBOL_LEN] = "ixgbe_run_xdp";
module_param_string(symbol, symbol, sizeof(symbol), 0644);

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
	struct sk_buff *skb = (struct sk_buff *)regs->di;
	struct net_device *dev = (struct net_device *)regs->si;
	struct packet_type *pt = (struct packet_type *)regs->dx;
	struct net_device *orig_dev = (struct net_device *)regs->cx;

	if (!strcmp(p->symbol_name, "ip_rcv")) {
		pr_info("<%s> skb->dev->name: %s, dev->name: %s, pt->func: %pK, orig_dev->name: %s\n",
			p->symbol_name, skb->dev->name, dev->name, pt->func, orig_dev->name);
	} else if (!strcmp(p->symbol_name, "bpf_prog_run_generic_xdp")) {
		struct sk_buff *skb = (struct sk_buff *)regs->di;
		u32 mac_len;
		struct ethhdr *eth = (struct ethhdr *)skb_mac_header(skb);

		mac_len = skb->data - skb_mac_header(skb);

		pr_info("<%s> skb_headroom(skb): %u, mac_len: %u\n",
			p->symbol_name, skb_headroom(skb), mac_len);

		pr_info("<%s> proto: 0x%04x\n",
			p->symbol_name, ntohs(eth->h_proto));
	} else if (!strcmp(p->symbol_name, "ixgbe_run_xdp")) {
	//	struct ixgbe_adapter *adapter = (struct ixgbe_adapter *)regs->di;
	//	struct ixgbe_ring *rx_ring = (struct ixgbe_ring *)regs->si;
		struct xdp_buff *xdp = (struct xdp_buff *)regs->dx;

		pr_info("<%s> data_hard_start: %lx, data: %lx, data_end: %lx, data_meta: %lx\n",
			p->symbol_name, (unsigned long)xdp->data_hard_start, (unsigned long)xdp->data,
			(unsigned long)xdp->data_end, (unsigned long)xdp->data_meta);
	}
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
 
	ret = register_kprobe(&kp);
	if (ret < 0) {
		pr_err("register_kprobe failed, returned %d\n", ret);
		return ret;
	}

	pr_info("Planted kprobe at %p\n", kp.addr);
	return 0;
}

static void __exit kprobe_exit(void)
{
	unregister_kprobe(&kp);
	pr_info("kprobe at %p unregistered\n", kp.addr);
}

module_init(kprobe_init)
module_exit(kprobe_exit)
MODULE_LICENSE("GPL");
