/*
 * 	get informations from kernel
 *		-- BigBro
 */

#include <linux/module.h>
#include <linux/timer.h>
#include <linux/delay.h>
#include <linux/netdevice.h>

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
	printk("dev %s: type: %u", dev->name, dev->type);
	if (dev->netdev_ops) {
		const struct net_device_ops *ops = dev->netdev_ops;

		printk("xmit: %pf, ioctl: %p"
			, ops->ndo_start_xmit, ops->ndo_do_ioctl);
	}
	printk("\n");
	dev_put(dev);
 	return 0;
}

static void __exit my_debug_cleanup(void)
{
	printk("Bye\n");
}

module_init(my_debug_init);
module_exit(my_debug_cleanup);
