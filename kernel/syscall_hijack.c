/*
 * BigBro/2022.02
 */

#include <linux/module.h>
#include <linux/unistd.h> /* for __NR_xxx */

#define SYSCALL_NUM	__NR_rename
//#define SET_REG_FOR_PERM

static unsigned long *sys_call_table;
static int (*orig_syscall_saved)(void);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("BigBro");
MODULE_DESCRIPTION("test for hijack of syscall");

#include "get_kallsyms_lookup_name.c"

#ifdef SET_REG_FOR_PERM
static unsigned int clear_and_return_cr0(void)
{
	unsigned int cr0 = 0;
	unsigned int ret;

	/* copy cr0 to rax and cr0 variable */
	asm volatile ("movq %%cr0, %%rax" : "=a"(cr0));

	ret = cr0;
	/* turn off writing protection */
	cr0 &= 0xfffeffff;

	/* copy cr0 variable to rax and copy rax to cr0 */
	asm volatile ("movq %%rax, %%cr0" :: "a"(cr0));

	/* return old value in cr0 register */
	return ret;
}

static void restore_cr0(unsigned int val)
{
	asm volatile ("movq %%rax, %%cr0" :: "a"(val));
}
#else
static int set_permission(unsigned long address, int rw, unsigned long *orig_pte_value)
{
	unsigned int level;

	pte_t *pte = lookup_address(address, &level);
	if (!pte)
		return -1;

	if (rw) {
		if (!(pte->pte & _PAGE_RW)) {
			*orig_pte_value = pte->pte;
			pte->pte |= _PAGE_RW;
			return 1;
		}
	} else {
		pte->pte = *orig_pte_value;
	}

	return 0;
}
#endif

static int sys_hijack(void)
{
    printk("successful hijack\n");
    return 0;
}

static void set_hijack(void)
{
#ifdef SET_REG_FOR_PERM
	{
		int orig_cr0;
		orig_cr0 = clear_and_return_cr0();
		sys_call_table[SYSCALL_NUM] = (unsigned long)&sys_hijack;
		restore_cr0(orig_cr0);
	}
#else
	{
		unsigned long orig;
		int ret;

		ret = set_permission((unsigned long)sys_call_table, 1, &orig);
		sys_call_table[SYSCALL_NUM] = (unsigned long)&sys_hijack;
		if (ret == 1) {
			set_permission((unsigned long)sys_call_table, 0, &orig);
		}
	}
#endif
}

static void cancel_hijack(void)
{
#ifdef SET_REG_FOR_PERM
	{
		int orig_cr0;

		orig_cr0 = clear_and_return_cr0();
		sys_call_table[SYSCALL_NUM] = (unsigned long)orig_syscall_saved;
		restore_cr0(orig_cr0);
	}
#else
	{
		unsigned long orig;
		int ret;

		ret = set_permission((unsigned long)sys_call_table, 1, &orig);
		sys_call_table[SYSCALL_NUM] = (unsigned long)orig_syscall_saved;
		if (ret == 1) {
			set_permission((unsigned long)sys_call_table, 0, &orig);
		}
	}
#endif
}

static int __init init_hijack_module(void)
{
	int ret;
	kallsyms_lookup_name_type pkallsyms_lookup_name;

	printk("loading hijack module\n");

	ret = get_kallsyms_lookup_name(&pkallsyms_lookup_name);
	if (ret) {
		printk("Can't get kallsyms_lookup_name symbol (ret = %d).\n", ret);
		return -1;
	}

	sys_call_table = (unsigned long *)pkallsyms_lookup_name("sys_call_table");
	orig_syscall_saved = (int(*)(void))(sys_call_table[SYSCALL_NUM]);

	set_hijack();
    return 0;
}

static void __exit exit_hijack_module(void)
{
    printk("unloading hijack module\n");
	cancel_hijack();
}

module_init(init_hijack_module);
module_exit(exit_hijack_module);
