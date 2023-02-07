/*
 * 	BigBro @2023
 */

#include <linux/module.h>
#include <linux/seq_file.h>
#include <linux/version.h>
#include <linux/proc_fs.h>
#include <net/net_namespace.h>
#include <net/ip.h>
#include <linux/kprobes.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("BigBro");
MODULE_DESCRIPTION("get proc important statistics");

static unsigned long (*pkallsyms_lookup_name)(const char *name) = NULL;

static int get_kallsyms_lookup_name(void)
{
	static struct kprobe kp = {
		.symbol_name = "kallsyms_lookup_name"
	};

	if (register_kprobe(&kp) < 0)
		return -1;

	unregister_kprobe(&kp);

	pkallsyms_lookup_name = (typeof(pkallsyms_lookup_name))kp.addr;

	return 0;
}

static struct snmp_mib mibs[] = {
	SNMP_MIB_ITEM("SyncookiesSent", LINUX_MIB_SYNCOOKIESSENT),
	SNMP_MIB_ITEM("SyncookiesRecv", LINUX_MIB_SYNCOOKIESRECV),
	SNMP_MIB_ITEM("SyncookiesFailed", LINUX_MIB_SYNCOOKIESFAILED),
	SNMP_MIB_ITEM("TW", LINUX_MIB_TIMEWAITED),
	SNMP_MIB_ITEM("TWRecycled", LINUX_MIB_TIMEWAITRECYCLED),
	SNMP_MIB_ITEM("TWKilled", LINUX_MIB_TIMEWAITKILLED),
	SNMP_MIB_ITEM("ListenOverflows", LINUX_MIB_LISTENOVERFLOWS),
	SNMP_MIB_ITEM("ListenDrops", LINUX_MIB_LISTENDROPS),
	SNMP_MIB_ITEM("TCPLostRetransmit", LINUX_MIB_TCPLOSTRETRANSMIT),
	SNMP_MIB_ITEM("TCPSackFailures", LINUX_MIB_TCPSACKFAILURES),
	SNMP_MIB_ITEM("TCPLossFailures", LINUX_MIB_TCPLOSSFAILURES),
	SNMP_MIB_ITEM("TCPFastRetrans", LINUX_MIB_TCPFASTRETRANS),
	SNMP_MIB_ITEM("TCPDeferAcceptDrop", LINUX_MIB_TCPDEFERACCEPTDROP),
	SNMP_MIB_ITEM("TCPTimeWaitOverflow", LINUX_MIB_TCPTIMEWAITOVERFLOW),
	SNMP_MIB_ITEM("TCPReqQFullDoCookies", LINUX_MIB_TCPREQQFULLDOCOOKIES),
	SNMP_MIB_ITEM("TCPReqQFullDrop", LINUX_MIB_TCPREQQFULLDROP),
};

static bool mib_filter(struct snmp_mib *mib)
{
	int i;

	for (i = 0; i < sizeof(mibs)/sizeof(mibs[0]); i++) {
		if (mib->entry == mibs[i].entry)
			return true;
	}

	return false;
}

static int system_stat_show(struct seq_file *seq, void *v)
{
	int i;
	struct net *net = seq->private;
	struct snmp_mib *snmp4_net_list;

	snmp4_net_list = (struct snmp_mib *)pkallsyms_lookup_name("snmp4_net_list");

	if (!snmp4_net_list)
		return 0;

	seq_puts(seq, "TcpExt:\n");

	for (i = 0; snmp4_net_list[i].name; i++) {
		if (!mib_filter(&snmp4_net_list[i]))
			continue;

		seq_printf(seq, "\t%-25s: %lu\n",
				snmp4_net_list[i].name,
				snmp_fold_field(net->mib.net_statistics,
				snmp4_net_list[i].entry));
	}

	return 0;
}

static int system_stat_show_complete(struct seq_file *seq, void *v)
{
	int i;
	struct net *net = seq->private;
	struct snmp_mib *snmp4_net_list;

	snmp4_net_list = (struct snmp_mib *)pkallsyms_lookup_name("snmp4_net_list");

	if (!snmp4_net_list)
		return 0;

	seq_puts(seq, "TcpExt:\n");

	for (i = 0; snmp4_net_list[i].name; i++) {
		seq_printf(seq, "\t%-25s: %lu\n",
				snmp4_net_list[i].name,
				snmp_fold_field(net->mib.net_statistics,
				snmp4_net_list[i].entry));
	}

	return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,18,0)
static int system_stat_open(struct inode *inode, struct file *file)
{
	return single_open_net(inode, file, system_stat_show);
}

static const struct file_operations system_stat_ops = {
	.owner	= THIS_MODULE,
	.open	= system_stat_open,
	.read	= seq_read,
	.llseek	= seq_lseek,
	.release = single_release_net,
};

static int system_stat_open_complete(struct inode *inode, struct file *file)
{
	return single_open_net(inode, file, system_stat_show_complete);
}

static const struct file_operations system_stat_ops_complete = {
	.owner	= THIS_MODULE,
	.open	= system_stat_open_complete,
	.read	= seq_read,
	.llseek	= seq_lseek,
	.release = single_release_net,
};
#endif

static int __init get_system_stat_init(void)
{
	if (get_kallsyms_lookup_name() < 0) {
		printk("Can't get kallsyms_lookup_name symbol.\n");
		return -1;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,18,0)
	if (!proc_create_net_single("private_stat", 0444, init_net.proc_net,
			system_stat_show, NULL)) {
		printk("Can't create /proc/net/private_stat.\n");
		goto proc_create_err;
	}

	if (!proc_create_net_single("private_stat_complete", 0444, init_net.proc_net,
			system_stat_show_complete, NULL)) {
		printk("Can't create /proc/net/private_stat.\n");
		goto proc_create_err;
	}
#else
	if (!proc_create("private_stat", 0644, init_net.proc_net, &system_stat_ops)) {
		printk("Can't create private/stat.\n");
		goto proc_create_err;
	}

	if (!proc_create("private_stat", 0644, init_net.proc_net, &system_stat_ops_complete)) {
		printk("Can't create private/stat.\n");
		goto proc_create_err;
	}
#endif

	printk("get_system_stat module loaded successfully\n");
	return 0;

proc_create_err:
	return -1;
}

static void __exit get_system_stat_cleanup(void)
{
	remove_proc_entry("private_stat", init_net.proc_net);

	printk("get_system_stat module unloaded successfully\n");
}

module_init(get_system_stat_init);
module_exit(get_system_stat_cleanup);

