/*
 * There are bugs, waiting to be fixed :)
 */

#include <linux/init.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/rbtree.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("BigBro");
MODULE_DESCRIPTION("Research for rbtree");

struct rb_data_s { 
     struct rb_node node;
     int key; 
};

static struct rb_root mytree = RB_ROOT;

#if 0
static struct rb_data_s *my_search(struct rb_root *root, int new)
{
	struct rb_node *node = root->rb_node;

	while (node) {
		struct rb_data_s *data = container_of(node, struct rb_data_s, node);

		if (data->key > new)
			node = node->rb_left;
		else if (data->key < new)
			node = node->rb_right;
		else
			return data;
	}
	return NULL;
}
#endif

static int my_insert(struct rb_root *root, struct rb_data_s *data)
{
	struct rb_node **new = &(root->rb_node), *parent=NULL;

	while (*new) {
		struct rb_data_s *this = container_of(*new, struct rb_data_s, node);

		parent = *new;
		if (this->key > data->key)
			new = &((*new)->rb_left);
		else if (this->key < data->key)
			new = &((*new)->rb_right);
		else
			return -1;
	}

	rb_link_node(&data->node, parent, new);
	rb_insert_color(&data->node, root);

	return 0;
}

static int __init my_init(void)
{
	int i;
	struct rb_data_s *data;
	struct rb_node *node;

	for (i = 0; i < 10; i++) {
		data = kmalloc(sizeof(struct rb_data_s), GFP_KERNEL);
		data->key = i;
		my_insert(&mytree, data);
	}

	for (node = rb_first(&mytree); node; node = rb_next(node)) 
		printk("key=%d\n", rb_entry(node, struct rb_data_s, node)->key);

	return 0;
}

static void __exit my_exit(void)
{
	struct rb_data_s *data;
	struct rb_node *node;

	for (node = rb_first(&mytree); node; node = rb_next(node)) {
		data = rb_entry(node, struct rb_data_s, node);
		if (data) {
			rb_erase(&data->node, &mytree);
			kfree(data);
		}
	}
}

module_init(my_init);
module_exit(my_exit);
