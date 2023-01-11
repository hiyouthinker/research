/*
 * BigBro @2023
 */

#include <linux/module.h>
#include <linux/seq_file.h>
#include <net/net_namespace.h>
#include <linux/kallsyms.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("BigBro");

static int __init call_usermodehelper_test_init(void)
{
	int rc;
	char target[64];
	char path[64] = "/bin/grep";
	char *argv[] = { path, target, "/proc/kallsyms", NULL };
	char *envp[] = { NULL };

	snprintf(target, sizeof(target), " T ip_rcv");

	printk("target: %s\n", target);

	rc = call_usermodehelper(path, argv, envp, UMH_WAIT_PROC);
	printk("ret: %d\n", rc);

	/*
	 * 512 => exited code 2
	 */
	if (rc != 0 && rc != 512) {
		printk("failed to execute command!\n");
	} else {
		printk("The command was executed successfully!\n");
	}

/*
	if (rc > 0) {
		if (rc & 0xff)
			printk(" received signal %d\n",
				 rc & 0x7f);
		else
			printk(" exited with code %d\n",
				 (rc >> 8) & 0xff);
	}
*/
	return 0;
}

static void __exit call_usermodehelper_test_cleanup(void)
{
	printk("Bye\n");
}

module_init(call_usermodehelper_test_init);
module_exit(call_usermodehelper_test_cleanup);
