/*
 * 	get informations from kernel
 *		-- BigBro
 */

#include <linux/module.h>
#include <linux/timer.h>
#include <linux/delay.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/version.h>

#define DRV_IXGBE

#ifdef GET_PRIVATE_DATA
/* for linux-4.15 */
#ifdef DRV_IXGBE
#include <ixgbe/ixgbe.h>
#else
#include <i40e/i40e.h>
#include <i40e/i40e_diag.h>
#endif
#endif

static char *name;
module_param(name, charp, 0);
MODULE_PARM_DESC(name, "interface name");

MODULE_LICENSE("GPL");
MODULE_AUTHOR("BigBro");
MODULE_DESCRIPTION("get infos from kernel");

static int __init get_common_infos_init(void)
{
	struct net_device *dev;
	struct in_device *in_dev;

	printk("Hello\n");

	if (!name) {
		name = "eth0";
	}

	dev = dev_get_by_name(current->nsproxy->net_ns, name);
	if (!dev) {
		printk("Can't find the interface %s\n", name);
		return 0;
 	}

	rcu_read_lock();

	in_dev = __in_dev_get_rcu(dev);
	if (in_dev) {
		bool nopolicy = IN_DEV_ORCONF(in_dev, NOPOLICY);

		printk("nopolicy for %s: %s\n", dev->name, nopolicy ? "yes" : "no");
	}

	rcu_read_unlock();

#if 0
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
#endif

#ifdef GET_PRIVATE_DATA
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
#endif

	dev_put(dev);
 	return 0;
}

static void __exit get_common_infos_cleanup(void)
{
	printk("Bye\n");
}

module_init(get_common_infos_init);
module_exit(get_common_infos_cleanup);
