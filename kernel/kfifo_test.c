/*
 * BigBro @2023
 *	-- reference linux/samples/kfifo/record-example.c
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/mutex.h>
#include <linux/kfifo.h>
#include <linux/version.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("BigBro");
MODULE_DESCRIPTION("kfifo test");

/*
 * This module shows how to create a variable sized record fifo.
 */

/* fifo size in elements (bytes) */
#define FIFO_SIZE	128

/* lock for procfs read access */
static DEFINE_MUTEX(read_lock);

/* lock for procfs write access */
static DEFINE_MUTEX(write_lock);

/*
 * define DYNAMIC in this example for a dynamically allocated fifo.
 *
 * Otherwise the fifo storage will be a part of the fifo structure.
 */
#if 0
#define DYNAMIC
#endif

/*
 * struct kfifo_rec_ptr_1 and  STRUCT_KFIFO_REC_1 can handle records of a
 * length between 0 and 255 bytes.
 *
 * struct kfifo_rec_ptr_2 and  STRUCT_KFIFO_REC_2 can handle records of a
 * length between 0 and 65535 bytes.
 */

#ifdef DYNAMIC
struct kfifo_rec_ptr_1 test;

#else
typedef STRUCT_KFIFO_REC_1(FIFO_SIZE) mytest;

static mytest test;
#endif

static const char *expected_result[] = {
	"a",
	"bb",
	"ccc",
	"dddd",
	"eeeee",
	"ffffff",
	"ggggggg",
	"hhhhhhhh",
	"iiiiiiiii",
	"jjjjjjjjjj",
};

static int __init testfunc(void)
{
	char		buf[100];
	unsigned int	i;
	unsigned int	ret;
	char info[] = "hello";

	printk(KERN_INFO "record fifo test start\n");

	kfifo_in(&test, info, sizeof(info));

	/* show the size of the next record in the fifo */
	printk(KERN_INFO "fifo peek len: %u\n", kfifo_peek_len(&test));

	/* put in variable length data */
	for (i = 0; i < 10; i++) {
		memset(buf, 'a' + i, i + 1);
		kfifo_in(&test, buf, i + 1);
	}

	/* skip first element of the fifo */
	printk(KERN_INFO "skip 1st element\n");
	kfifo_skip(&test);

	printk(KERN_INFO "fifo len: %u\n", kfifo_len(&test));

	/* show the first record without removing from the fifo */
	ret = kfifo_out_peek(&test, buf, sizeof(buf));
	if (ret)
		printk(KERN_INFO "%.*s\n", ret, buf);

	/* check the correctness of all values in the fifo */
	i = 0;
	while (!kfifo_is_empty(&test)) {
		ret = kfifo_out(&test, buf, sizeof(buf));
		buf[ret] = '\0';
		printk(KERN_INFO "item = %.*s\n", ret, buf);
		if (strcmp(buf, expected_result[i++])) {
			printk(KERN_WARNING "value mismatch: test failed\n");
			return -EIO;
		}
	}
	if (i != ARRAY_SIZE(expected_result)) {
		printk(KERN_WARNING "size mismatch: test failed\n");
		return -EIO;
	}
	printk(KERN_INFO "test passed\n");

	return 0;
}

static ssize_t fifo_write(struct file *file, const char __user *buf,
						size_t count, loff_t *ppos)
{
	int ret;
	unsigned int copied;

	if (mutex_lock_interruptible(&write_lock))
		return -ERESTARTSYS;

	ret = kfifo_from_user(&test, buf, count, &copied);

	mutex_unlock(&write_lock);
	if (ret)
		return ret;

	return copied;
}

static ssize_t fifo_read(struct file *file, char __user *buf,
						size_t count, loff_t *ppos)
{
	int ret;
	unsigned int copied;

	if (mutex_lock_interruptible(&read_lock))
		return -ERESTARTSYS;

	ret = kfifo_to_user(&test, buf, count, &copied);

	mutex_unlock(&read_lock);
	if (ret)
		return ret;

	return copied;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
static const struct proc_ops fifo_proc_ops = {
	.proc_read	= fifo_read,
	.proc_write	= fifo_write,
	.proc_lseek	= noop_llseek,
};
#else
static const struct file_operations fifo_fops = {
	.owner		= THIS_MODULE,
	.read		= fifo_read,
	.write		= fifo_write,
	.llseek		= noop_llseek,
};
#endif

static int __init kfifo_test_init(void)
{
#ifdef DYNAMIC
	int ret;

	ret = kfifo_alloc(&test, FIFO_SIZE, GFP_KERNEL);
	if (ret) {
		printk(KERN_ERR "error kfifo_alloc\n");
		return ret;
	}
#else
	INIT_KFIFO(test);
#endif

	if (testfunc() < 0) {
#ifdef DYNAMIC
		kfifo_free(&test);
#endif
		return -EIO;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
	if (proc_create("kfifo_test", 0, NULL, &fifo_proc_ops) == NULL)
#else
	if (proc_create("kfifo_test", 0, NULL, &fifo_fops) == NULL)
#endif
	{
#ifdef DYNAMIC
		kfifo_free(&test);
#endif
		return -ENOMEM;
	}

	return 0;
}

static void __exit kfifo_test_exit(void)
{
	remove_proc_entry("kfifo_test", NULL);
#ifdef DYNAMIC
	kfifo_free(&test);
#endif
}

module_init(kfifo_test_init);
module_exit(kfifo_test_exit);
