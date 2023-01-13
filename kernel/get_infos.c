/*
 * 	get informations from kernel
 *		-- BigBro
 */

#include <linux/module.h>
#include <linux/timer.h>
#include <linux/delay.h>
#include <linux/netdevice.h>

#define DRV_IXGBE

/* for linux-4.15 */
#ifdef DRV_IXGBE
#include <ixgbe/ixgbe.h>
#else
#include <i40e/i40e.h>
#include <i40e/i40e_diag.h>
#endif

static char *name;
module_param(name, charp, 0);
MODULE_PARM_DESC(name, "interface name");

MODULE_LICENSE("GPL");
MODULE_AUTHOR("BigBro");
MODULE_DESCRIPTION("get infos from kernel");

static int __init my_debug_init(void)
{
	struct net_device *dev;

	printk("Hello\n");

	if (!name) {
		name = "eth0";
	}

	dev = dev_get_by_name(current->nsproxy->net_ns, name);
	if (!dev) {
		printk("Can't find the interface %s\n", name);
		return 0;
 	}

	printk("dev %s: type: %u, features: %llx\n", dev->name, dev->type, dev->features);

	if (dev->features & NETIF_F_SG) {
		printk("NETIF_F_SG is on\n");
	} else {
		printk("NETIF_F_SG is off\n");
	}

	if (dev->features & NETIF_F_FRAGLIST) {
		printk("NETIF_F_FRAGLIST is on\n");
	} else {
		printk("NETIF_F_FRAGLIST is off\n");
	}

	if (dev->netdev_ops) {
		const struct net_device_ops *ops = dev->netdev_ops;

		printk("xmit: %pf, ioctl: %p\n"
			, ops->ndo_start_xmit, ops->ndo_do_ioctl);
	}

#ifdef DRV_IXGBE
	{
		struct ixgbe_adapter *adapter;

		adapter = netdev_priv(dev);
		printk("atr_sample_rate: %u\n", adapter->atr_sample_rate);
	}
#else
	{
		struct i40e_netdev_priv *np;
		struct i40e_vsi *vsi;

		np = netdev_priv(dev);
		vsi = np->vsi;

		printk("vsi->rss_size: %u\n", vsi->rss_size);
	}
#endif

	dev_put(dev);
 	return 0;
}

static void __exit my_debug_cleanup(void)
{
	printk("Bye\n");
}

module_init(my_debug_init);
module_exit(my_debug_cleanup);
