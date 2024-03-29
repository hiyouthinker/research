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

#define GET_PRIVATE_DATA

#ifdef GET_PRIVATE_DATA
#ifdef DRV_IXGBE
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,15,0)
#include <ixgbe_5.15/ixgbe.h>
#else
/* for linux-4.15 */
#include <ixgbe/ixgbe.h>
#endif
#else
#include <i40e/i40e.h>
#include <i40e/i40e_diag.h>
#endif
#endif

#include "get_kallsyms_lookup_name.c"

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
	void **ethtool_phy_ops;
	int ret;
	kallsyms_lookup_name_type pkallsyms_lookup_name;

	printk("Hello\n");

	ret = get_kallsyms_lookup_name(&pkallsyms_lookup_name);
	if (ret) {
		printk("Can't get kallsyms_lookup_name symbol (ret = %d).\n", ret);
		return -1;
	}

	ethtool_phy_ops = (void **)pkallsyms_lookup_name("ethtool_phy_ops");
	if (!ethtool_phy_ops) {
		printk("Can't get ethtool_phy_ops symbol.\n");
		return -1;
	}

	if (!name) {
		name = "eth12";
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

	printk("%s: dev->phydev: %pK, ethtool_phy_ops: %pK @%pK, netdev_ops: %pK\n",
		dev->name, dev->phydev,
		*ethtool_phy_ops,
		ethtool_phy_ops,
		dev->netdev_ops);

	printk("%s: num_tc: %d\n", dev->name, dev->num_tc);

	if (dev->netdev_ops) {
		printk("%s: ndo_rx_flow_steer: %pK\n", dev->name, dev->netdev_ops->ndo_rx_flow_steer);
	}

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
		printk("num_rx_queues: %u\n", adapter->num_rx_queues);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,15,0)
		if (adapter->num_rx_queues > 0) {
			printk("rx_ring[0]->rx_offset: %u\n", adapter->rx_ring[0]->rx_offset);
		}
#endif
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
