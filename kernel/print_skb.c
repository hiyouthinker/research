#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <net/ip.h>

static unsigned int
printk_skb(void *priv, struct sk_buff *skb,
	     const struct nf_hook_state *state)
{
	static int i = 0, offset;
	struct iphdr _iph;
	const struct iphdr *ih;

	if (i < 100) {
		offset = 0;

		ih = skb_header_pointer(skb, offset, sizeof(_iph), &_iph);
		if (ih == NULL) {
			printk("TRUNCATED (%d)\n", i);
			return NF_ACCEPT;
		}

		if (ih->protocol == IPPROTO_TCP) {
			struct tcphdr _tcph;
			const struct tcphdr *th;

			offset = ih->ihl * 4;

			if (ih->ihl != 5 || (ntohs(ih->frag_off) & IP_OFFSET))
				return NF_ACCEPT;

			th = skb_header_pointer(skb, offset, sizeof(_tcph), &_tcph);
			if (th == NULL) {
				printk("(%d) SRC=%pI4 DST=%pI4 PROTO=%u INCOMPLETE\n",
					i, &ih->saddr, &ih->daddr, ih->protocol);
				return NF_ACCEPT;
			}

			if (ntohs(th->dest) == 22)
				return NF_ACCEPT;

			printk("(%d) SRC=%pI4 DST=%pI4 PROTO=%u SPT=%u DPT=%u\n",
					i, &ih->saddr, &ih->daddr, ih->protocol,
					ntohs(th->source), ntohs(th->dest));
		} else
			printk("(%d) SRC=%pI4 DST=%pI4 PROTO=%u\n", i, &ih->saddr, &ih->daddr, ih->protocol);

		i++;
	}

	return NF_ACCEPT;
}

static const struct nf_hook_ops my_ops[] = {
	{
		.hook		= printk_skb,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_PRE_ROUTING,
		.priority	= 500,
	},
};

int __init init_test(void)
{
	printk("loading init_test\n");

	if (nf_register_net_hooks(&init_net, my_ops, ARRAY_SIZE(my_ops)) < 0) {
		printk("nf_register_net_hooks failed!\n");
	}

	return 0;
}

void __exit cleanup_test(void)
{
	printk("unloading cleanup_test\n");
	nf_unregister_net_hooks(&init_net, my_ops, ARRAY_SIZE(my_ops));
}

MODULE_LICENSE("GPL");

module_init(init_test);
module_exit(cleanup_test);
