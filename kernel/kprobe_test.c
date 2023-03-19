/*
 * BigBro @2023
 */

#define pr_fmt(fmt) "%s: " fmt, __func__

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/netdevice.h>

#define MAX_SYMBOL_LEN	64
static char symbol[MAX_SYMBOL_LEN] = "ip_rcv";
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

	if (!strcmp(p->symbol_name, "ip_rcv"))
		pr_info("<%s> skb->dev->name: %s, dev->name: %s, pt->func: %pK, orig_dev->name: %s\n",
			p->symbol_name, skb->dev->name, dev->name, pt->func, orig_dev->name);
	else
		pr_info("<%s> di/si/dx/cx = 0x%lx/0x%lx/0x%lx/0x%lx\n",
			p->symbol_name, regs->di, regs->si, regs->dx, regs->cx);
#endif
	return 0;
}

/* kprobe post_handler: called after the probed instruction is executed */
static void __kprobes handler_post(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
#ifdef CONFIG_X86
	pr_info("<%s> di/si/dx/cx = 0x%lx/0x%lx/0x%lx/0x%lx\n",
		p->symbol_name, regs->di, regs->si, regs->dx, regs->cx);
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
