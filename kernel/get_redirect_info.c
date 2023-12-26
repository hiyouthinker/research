/*
 * BigBro @2023
 */

#include <linux/module.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/filter.h>
#include <linux/kprobes.h>
#include <linux/bpf.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,15,0)

#include "get_kallsyms_lookup_name.c"

static struct bpf_map *(*pbpf_map_get)(u32 ufd) = NULL;
static void *(*pcpu_map_lookup_elem)(struct bpf_map *map, void *key) = NULL;

MODULE_LICENSE("GPL");
MODULE_AUTHOR("BigBro");
MODULE_DESCRIPTION("get ebpf redirect cpu/dev info");

/*
 * from kernel/bpf/cpumap.c
 */
/* Struct for every remote "destination" CPU in map */
struct bpf_cpu_map_entry {
	u32 cpu;    /* kthread CPU and map index */
	int map_id; /* Back reference to map */

	/* XDP can run multiple RX-ring queues, need __percpu enqueue store */
	struct xdp_bulk_queue __percpu *bulkq;

	struct bpf_cpu_map *cmap;

	/* Queue with potential multi-producers, and single-consumer kthread */
	struct ptr_ring *queue;
	struct task_struct *kthread;

	struct bpf_cpumap_val value;
	struct bpf_prog *prog;

	atomic_t refcnt; /* Control when this struct can be free'ed */
	struct rcu_head rcu;

	struct work_struct kthread_stop_wq;
};

static struct proc_dir_entry *redirect_dir;

static int map_fd = -1;

static ssize_t 
redirect_cpu_proc_write(struct file *file, const char __user *buffer,
		size_t count, loff_t *f_pos)
{
	char in[32] = {0};
	char *p;

	if (copy_from_user(in, buffer,
		count >= sizeof(in) ? sizeof(in) - 1 : count))
		return -EFAULT;

	p = strchr(in, '\n');
	if (p)
		*p = '\0';

	map_fd = simple_strtol(in, NULL, 0);
//	printk("%s: input: %s/%d\n", __func__, in, map_fd);

	if (map_fd < 0)
		return -EINVAL;

	return count;
}

static int
redirect_cpu_proc_show(struct seq_file *m, void *v)
{
	struct bpf_map *map;
	struct bpf_cpu_map_entry *rcpu;
	struct ptr_ring *queue;
	void *value;
	int i;

//	printk("map_fd: %d\n", map_fd);

	map = pbpf_map_get(map_fd);
	if (IS_ERR(map)) {
		return PTR_ERR(map);
	}

	rcu_read_lock();

	for_each_possible_cpu(i) {
#if 0
		ri = per_cpu_ptr(&bpf_redirect_info, i);
		rcpu = ri->tgt_value;

		if (rcpu) {
			queue = rcpu->queue;
			if (!queue) {
				printk("CPU%d: queue is nullptr\n", i);
			} else {
				printk("CPU%d: producer: %d\n", i, queue->producer);
			}
		}
#else
		value = pcpu_map_lookup_elem(map, &i);
		if (value) {
			rcpu = container_of(value, struct bpf_cpu_map_entry, value);
			queue = rcpu->queue;

			if (!queue) {
				seq_printf(m, "CPU%d: queue is nullptr\n", i);
			} else {
				int batch, size, tail, head, producer, unread;

				batch = queue->batch;
				size = queue->size;
				tail = queue->consumer_tail;
				head = queue->consumer_head;
				producer = queue->producer;

				unread = producer - head;
				if (unread < 0) {
					unread += size;
				}

				seq_printf(m, "CPU%d: batch/size: %d/%d, tail/head: %d/%d, producer: %d, unread data length: %d\n",
						i, batch, size, tail, head, producer, unread);
			}
		}
#endif
	}

	rcu_read_unlock();

	bpf_map_put(map);

	return 0;
}

static int
redirect_cpu_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, redirect_cpu_proc_show, NULL);
}

static const struct proc_ops redirect_cpu_proc_ops = {
	.proc_open	= redirect_cpu_proc_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release = single_release,
	.proc_write	= redirect_cpu_proc_write,
};

static int redirect_init(void)
{
	struct proc_dir_entry *pde;
	kallsyms_lookup_name_type pkallsyms_lookup_name;
	int ret = get_kallsyms_lookup_name(&pkallsyms_lookup_name);

	if (ret) {
		printk("Can't get kallsyms_lookup_name symbol (ret = %d).\n", ret);
		goto err;
	}

	pbpf_map_get = (typeof(pbpf_map_get))pkallsyms_lookup_name("bpf_map_get");
	if (!pbpf_map_get) {
		printk("Can't get bpf_map_get symbol.\n");
		goto err;
	}
	printk("pbpf_map_get: %pK\n", pbpf_map_get);

	pcpu_map_lookup_elem = (typeof(pcpu_map_lookup_elem))pkallsyms_lookup_name("cpu_map_lookup_elem");
	if (!pcpu_map_lookup_elem) {
		printk("Can't get cpu_map_lookup_elem symbol.\n");
		goto err;
	}
	printk("pcpu_map_lookup_elem: %pK\n", pcpu_map_lookup_elem);

	redirect_dir = proc_mkdir("redirect", init_net.proc_net);
	if (!redirect_dir) {
		printk("Can't create redirect directory.\n");
		goto proc_mkdir_err;
	}

	pde = proc_create("cpu", 0644, redirect_dir, &redirect_cpu_proc_ops);
	if (!pde) {
		printk("Can't create redirect/cpu.\n");
		goto proc_create_err;
	}

	printk("redirect loaded\n");

	return 0;

proc_create_err:
	remove_proc_entry("redirect", NULL);
proc_mkdir_err:
err:
	return -1;
}

static void redirect_exit(void)
{
	remove_proc_entry("cpu", redirect_dir);
	remove_proc_entry("redirect", init_net.proc_net);

	printk("redirect unloaded\n");
}

module_init(redirect_init);
module_exit(redirect_exit);
#else
MODULE_LICENSE("GPL");
#endif
