/*
 * BigBro @2021-2023
 */

#include <linux/module.h>
#include <linux/timer.h>
#include <linux/delay.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <net/net_namespace.h>
#include <linux/version.h>

static long pid1, pid2, fd1, fd2;
module_param(pid1, long, 0);
module_param(pid2, long, 0);
module_param(fd1, long, 0);
module_param(fd2, long, 0);

MODULE_PARM_DESC(pid, "pid of proccess");
MODULE_PARM_DESC(fd1, "fd for listen");

MODULE_LICENSE("GPL");
MODULE_AUTHOR("BigBro");
MODULE_DESCRIPTION("for debug");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)
static struct file *__fget_files(struct files_struct *files, unsigned int fd,
				 fmode_t mask, unsigned int refs)
{
	struct file *file;

	rcu_read_lock();
loop:
	file = files_lookup_fd_rcu(files, fd);
	if (file) {
		/* File object ref couldn't be taken.
		 * dup2() atomicity guarantee is the reason
		 * we loop to catch the new file (or NULL pointer)
		 */
		if (file->f_mode & mask)
			file = NULL;
		else if (!get_file_rcu_many(file, refs))
			goto loop;
	}
	rcu_read_unlock();

	return file;
}

static inline struct file *__fget(unsigned int fd, fmode_t mask, unsigned int refs, struct task_struct *task)
{
	return __fget_files(task->files, fd, mask, refs);
}

static unsigned long __fget_light(unsigned int fd, fmode_t mask, struct task_struct *task)
{
	struct files_struct *files = current->files;
	struct file *file;

	if (atomic_read(&files->count) == 1) {
		file = files_lookup_fd_raw(files, fd);
		if (!file || unlikely(file->f_mode & mask))
			return 0;
		return (unsigned long)file;
	} else {
		file = __fget(fd, mask, 1, task);
		if (!file)
			return 0;
		return FDPUT_FPUT | (unsigned long)file;
	}
}
#else
static struct file *__fget(unsigned int fd, fmode_t mask, struct task_struct *task)
{
	struct files_struct *files = task->files;
	struct file *file;

	rcu_read_lock();
loop:
	file = fcheck_files(files, fd);
	if (file) {
		/* File object ref couldn't be taken.
		 * dup2() atomicity guarantee is the reason
		 * we loop to catch the new file (or NULL pointer)
		 */
		if (file->f_mode & mask)
			file = NULL;
		else if (!get_file_rcu(file))
			goto loop;
	}
	rcu_read_unlock();

	return file;
}

static unsigned long __fget_light(unsigned int fd, fmode_t mask, struct task_struct *task)
{
	struct files_struct *files = task->files;
	struct file *file;

	if (atomic_read(&files->count) == 1) {
		file = __fcheck_files(files, fd);
		if (!file || unlikely(file->f_mode & mask))
			return 0;
		return (unsigned long)file;
	} else {
		file = __fget(fd, mask, task);
		if (!file)
			return 0;
		return FDPUT_FPUT | (unsigned long)file;
	}
}
#endif

static unsigned long __my_fdget(unsigned int fd, struct task_struct *task)
{
	return __fget_light(fd, FMODE_PATH, task);
}

static inline struct fd my_fdget(unsigned int fd, struct task_struct *task)
{
	return __to_fd(__my_fdget(fd, task));
}

/* from net/socket.c */
static struct socket *sockfd_lookup_light(int fd, int *err, int *fput_needed, struct task_struct *ts)
{
	struct fd f = my_fdget(fd, ts);
	struct socket *sock;

	*err = -EBADF;
	if (f.file) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)
		sock = sock_from_file(f.file);
#else
		sock = sock_from_file(f.file, err);
#endif
		if (likely(sock)) {
			*fput_needed = f.flags;
			return sock;
		}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)
		*err = -ENOTSOCK;
#endif
		fdput(f);
	}
	return NULL;
}

#if 0
static struct task_struct *find_task_by_pid_ns(pid_t nr, struct pid_namespace *ns)
{
	RCU_LOCKDEP_WARN(!rcu_read_lock_held(),
			 "find_task_by_pid_ns() needs rcu_read_lock() protection");
	return pid_task(find_pid_ns(nr, ns), PIDTYPE_PID);
}
#endif

static int __init get_socket_info_init(void)
{
	struct task_struct *ts;
	int err, fput_needed;

	rcu_read_lock();
	if (pid1) {
		ts = find_task_by_pid_ns(pid1, &init_pid_ns);
		if (ts) {
			printk("%s/%ld: socket: %ld/%p\n",
				ts->comm, pid1, fd1,
				sockfd_lookup_light(fd1, &err, &fput_needed, ts));
		}
	}

	if (pid2) {
		ts = find_task_by_pid_ns(pid2, &init_pid_ns);
		if (ts) {
			printk("%s/%ld: socket: %ld/%p\n",
				ts->comm, pid2, fd2,
				sockfd_lookup_light(fd2, &err, &fput_needed, ts));
		}
	}
	rcu_read_unlock();

	printk("Hello\n");
	return 0;
}

static void __exit get_socket_info_cleanup(void)
{
	printk("Bye\n");
}

module_init(get_socket_info_init);
module_exit(get_socket_info_cleanup);
