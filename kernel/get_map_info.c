/*
 * BigBro @2023
 */

#include <linux/version.h>
#include <linux/module.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,15,0)
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <net/net_namespace.h>
#include <linux/jhash.h> // for jhash
#include <linux/bpf.h>
#include <linux/math.h>   // for round_up
#include <linux/filter.h> // for struct bpf_prog
#include <linux/rculist_nulls.h> // for hlist_nulls_first_rcu

#include <percpu_freelist.h>
#include <bpf_lru_list.h>

#include "get_kallsyms_lookup_name.c"

static struct bpf_map *(*pbpf_map_get)(u32 ufd) = NULL;

MODULE_LICENSE("GPL");
MODULE_AUTHOR("BigBro");
MODULE_DESCRIPTION("print map infos");

/* Helpers to get the local list index */
#define LOCAL_LIST_IDX(t)	((t) - BPF_LOCAL_LIST_T_OFFSET)
#define LOCAL_FREE_LIST_IDX	LOCAL_LIST_IDX(BPF_LRU_LOCAL_LIST_T_FREE)
#define LOCAL_PENDING_LIST_IDX	LOCAL_LIST_IDX(BPF_LRU_LOCAL_LIST_T_PENDING)
#define IS_LOCAL_LIST_TYPE(t)	((t) >= BPF_LOCAL_LIST_T_OFFSET)

struct bucket {
	struct hlist_nulls_head head;
	union {
		raw_spinlock_t raw_lock;
		spinlock_t     lock;
	};
};

#define HASHTAB_MAP_LOCK_COUNT 8
#define HASHTAB_MAP_LOCK_MASK (HASHTAB_MAP_LOCK_COUNT - 1)

struct htab_elem {
	union {
		struct hlist_nulls_node hash_node;
		struct {
			void *padding;
			union {
				struct bpf_htab *htab;
				struct pcpu_freelist_node fnode;
				struct htab_elem *batch_flink;
			};
		};
	};
	union {
		struct rcu_head rcu;
		struct bpf_lru_node lru_node;
	};
	u32 hash;
	char key[] __aligned(8);
};

struct bpf_htab {
	struct bpf_map map;
	struct bucket *buckets;
	void *elems;
	union {
		struct pcpu_freelist freelist;
		struct bpf_lru lru;
	};
	struct htab_elem *__percpu *extra_elems;
	atomic_t count;	/* number of elements in this hashtable */
	u32 n_buckets;	/* number of hash buckets */
	u32 elem_size;	/* size of each element in bytes */
	u32 hashrnd;
	struct lock_class_key lockdep_key;
	int __percpu *map_locked[HASHTAB_MAP_LOCK_COUNT];
};

static struct proc_dir_entry *map_dir;
static int map_fd = -1;

static ssize_t 
map_print_proc_write(struct file *file, const char __user *buffer,
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
	printk("%s: input: %s/%d\n", __func__, in, map_fd);

	if (map_fd < 0)
		return -EINVAL;

	return count;
}

static struct list_head *free_list(struct bpf_common_lru *clru)
{
	return &clru->lru_list.lists[BPF_LRU_LIST_T_FREE];
}

static struct list_head *active_list(struct bpf_common_lru *clru)
{
	return &clru->lru_list.lists[BPF_LRU_LIST_T_ACTIVE];
}

static struct list_head *inactive_list(struct bpf_common_lru *clru)
{
	return &clru->lru_list.lists[BPF_LRU_LIST_T_INACTIVE];
}

static struct list_head *local_free_list(struct bpf_lru_locallist *loc_l)
{
	return &loc_l->lists[LOCAL_FREE_LIST_IDX];
}

static struct list_head *local_pending_list(struct bpf_lru_locallist *loc_l)
{
	return &loc_l->lists[LOCAL_PENDING_LIST_IDX];
}

static inline struct bucket *__select_bucket(struct bpf_htab *htab, u32 hash)
{
	return &htab->buckets[hash & (htab->n_buckets - 1)];
}

static inline struct hlist_nulls_head *select_bucket(struct bpf_htab *htab, u32 hash)
{
	return &__select_bucket(htab, hash)->head;
}

static inline u32 htab_map_hash(const void *key, u32 key_len, u32 hashrnd)
{
	return jhash(key, key_len, hashrnd);
}

static int get_first_key(struct bpf_htab *htab, struct seq_file *m)
{
	int i = 0, j = 0;
	u32 hash, key_size;
	struct hlist_nulls_head *head;
	struct htab_elem *next;

	key_size = htab->map.key_size;

	for (; i < htab->n_buckets; i++) {
		char buf[512] = {0};
		int l = 0;

		head = select_bucket(htab, i);

		/* pick first element in the bucket */
		next = hlist_nulls_entry_safe(rcu_dereference_raw(hlist_nulls_first_rcu(head)),
					  struct htab_elem, hash_node);
		if (next) {
			/* if it's not empty, just return it */
			for (j = 0; j < key_size; j++) {
				l += snprintf(buf + l, sizeof(buf), "%02x ", (0xff & next->key[j]));
			}
			seq_printf(m, "[%s]\n", buf);

			hash = htab_map_hash(next->key, key_size, htab->hashrnd);

			seq_printf(m, "hash: %u/%u, hash & 0x%04x: %u, index: %d\n",
				hash,
				next->hash,
				htab->n_buckets - 1,
				hash & (htab->n_buckets - 1),
				i);
			/* got first key */
			return 1;
		}
	}

	return 0;
}

static int map_print_proc_show(struct seq_file *m, void *v)
{
	struct bpf_map *map;
	struct bpf_htab *htab;
	struct bpf_lru_locallist *loc_l;
	struct bpf_common_lru *clru;
	struct bpf_lru_node *node;
	unsigned long flags;
	int cpu, free_count = 0;
	int local_pending_count, local_free_count, total_pending_count = 0, total_free_count = 0;
	int active_ref1 = 0, inactive_ref1 = 0, local_pending_ref1 = 0;
	int active_ref2 = 0, active_total = 0, inactive_total = 0;
	int total = 0;
	u32 key_size;

	printk("map_fd: %d\n", map_fd);

	map = pbpf_map_get(map_fd);
	if (IS_ERR(map)) {
		return PTR_ERR(map);
	}

	htab = (struct bpf_htab *)map;

	seq_printf(m, "map_fd: %d, map type: %d, max_entries: %u, bucket: %u\n",
		map_fd,
		htab->map.map_type,
		htab->map.max_entries,
		htab->n_buckets);

	key_size = htab->map.key_size;

	seq_printf(m, "key_size/value_size: %u/%u\n", key_size, htab->map.value_size);

	get_first_key(htab, m);

	clru = &htab->lru.common_lru;

	list_for_each_entry(node, free_list(clru), list) {
		free_count++;
	}

	list_for_each_entry_reverse(node, active_list(clru), list) {
		if (node->ref) {
			active_ref1++;
			if (active_total < 128)
				active_ref2++;
		}
		active_total++;
	}

	list_for_each_entry(node, inactive_list(clru), list) {
		if (node->ref)
			inactive_ref1++;
		inactive_total++;
	}

	for_each_possible_cpu(cpu) {
		local_pending_count = 0;
		local_free_count = 0;
		local_pending_ref1 = 0;

		loc_l = per_cpu_ptr(clru->local_list, cpu);

		raw_spin_lock_irqsave(&loc_l->lock, flags);

		list_for_each_entry(node, local_pending_list(loc_l), list) {
			local_pending_count++;
			if (node->ref)
				local_pending_ref1++;
		}

		list_for_each_entry(node, local_free_list(loc_l), list) {
			local_free_count++;
		}

		total_pending_count += local_pending_count;
		total_free_count += local_free_count;

		raw_spin_unlock_irqrestore(&loc_l->lock, flags);

		seq_printf(m,
			"CPU%d\n"
			"\t%-13s: %d (ref: %d)\n"
			"\t%-13s: %d\n",
			cpu,
			"LOCAL_PENDING",
			local_pending_count,
			local_pending_ref1,
			"LOCAL_FREE",
			local_free_count);
	}

	total = clru->lru_list.counts[BPF_LRU_LIST_T_ACTIVE] + clru->lru_list.counts[BPF_LRU_LIST_T_INACTIVE] +
			free_count + total_pending_count + total_free_count;

	seq_printf(m,
		"Global\n"
		"\t%-15s: %d/%d (ref: %d/%d)\n"
		"\t%-15s: %d/%d (ref: %d)\n"
		"\t%-15s: %d\n"
		"\t%-15s: %d\n"
		"\t%-15s: %d\n"
		"\t%-15s: %d\n",
		"ACTIVE",
		clru->lru_list.counts[BPF_LRU_LIST_T_ACTIVE],
		active_total,
		active_ref1, active_ref2,
		"INACTIVE",
		clru->lru_list.counts[BPF_LRU_LIST_T_INACTIVE],
		inactive_total,
		inactive_ref1,
		"FREE",
		free_count,
		"ALL_CPU_PENDING",
		total_pending_count,
		"ALL_CPU_FREE",
		total_free_count,
		"TOTAL",
		total);

	bpf_map_put(map);

	return 0;
}

static int
map_print_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, map_print_proc_show, NULL);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
static const struct proc_ops map_print_proc_ops = {
	.proc_open	= map_print_proc_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release = single_release,
	.proc_write	= map_print_proc_write,
};
#else
static const struct file_operations map_print_proc_ops = {
	.owner	= THIS_MODULE,
	.open	= map_print_proc_open,
	.read	= seq_read,
	.llseek	= seq_lseek,
	.release = single_release,
	.write	= map_print_proc_write,
};
#endif

static int __init get_map_info_init(void)
{
	struct proc_dir_entry *pde;
	kallsyms_lookup_name_type pkallsyms_lookup_name;

	int ret = get_kallsyms_lookup_name(&pkallsyms_lookup_name);

	if (ret) {
		printk("Can't get kallsyms_lookup_name symbol (ret = %d).\n", ret);
		return -1;
	}

	pbpf_map_get = (typeof(pbpf_map_get))pkallsyms_lookup_name("bpf_map_get");
	if (!pbpf_map_get) {
		printk("Can't get bpf_map_get symbol.\n");
		return -1;
	}
	printk("pbpf_map_get: %pK\n", pbpf_map_get);

	map_dir = proc_mkdir("map", init_net.proc_net);
	if (!map_dir) {
		printk("Can't create map dir.\n");
		goto proc_mkdir_err;
	}

	pde = proc_create("print_map", 0644, map_dir, &map_print_proc_ops);
	if (!pde) {
		printk("Can't create map/print_map.\n");
		goto proc_create_err;
	}

	printk("get_map_info module loaded successfully\n");
	return 0;

proc_create_err:
	remove_proc_entry("map", NULL);
proc_mkdir_err:
	return -1;
}

static void __exit get_map_info_cleanup(void)
{
	remove_proc_entry("print_map", map_dir);
	remove_proc_entry("map", init_net.proc_net);

	printk("get_map_info module unloaded successfully\n");
}

module_init(get_map_info_init);
module_exit(get_map_info_cleanup);
#else
MODULE_LICENSE("GPL");
#endif
