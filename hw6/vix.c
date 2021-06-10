// SPDX-License-Identifier: GPL-2.0
// Author: Harry Chong (Student ID: 14158124)
#include <linux/module.h>
#include <linux/debugfs.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/fs.h>

static struct dentry *dir;
static int last_id;

struct vix_dev {
	int id;
	char *name;

	struct list_head list;
};

static DEFINE_SPINLOCK(lock);
static LIST_HEAD(vix_dev_list);

static ssize_t vix_devices_read(struct file *filp, char __user *buf, size_t count, loff_t *ppos)
{
	char str[256];
	ssize_t ret = 0;
	struct vix_dev *cur = NULL;

	// Generate list of devices onto terminal
	spin_lock(&lock);
	list_for_each_entry(cur, &vix_dev_list, list) {
		ret += snprintf(str+ret, 256, "%03d: %s\n", cur->id, cur->name);
	}
	spin_unlock(&lock);

	str[ret] = '\0'; // Add null terminator

	return simple_read_from_buffer(buf, count, ppos, str, strlen(str));
}

static ssize_t vix_devices_write(struct file *filp, const char __user *buf, size_t count, loff_t *ppos)
{
	int ret;
	struct vix_dev *dev = kmalloc(sizeof(*dev), GFP_KERNEL);

	if (!dev)
		return -ENOMEM;

	dev->id = last_id;
	last_id++;

	dev->name = kmalloc(sizeof(char) * (count+1), GFP_KERNEL);
	if (!dev->name) {
		kfree(dev);
		return -ENOMEM;
	}

	ret = simple_write_to_buffer(dev->name, count, ppos, buf, count);
	if (ret == 0) {
		kfree(dev->name);
		kfree(dev);
		return ret;
	}

	dev->name[ret] = '\0'; // Add null terminator

	spin_lock(&lock);
	list_add_tail(&dev->list, &vix_dev_list);
	spin_unlock(&lock);

	return ret;
}

static const struct file_operations vix_devices_fops = {
	.owner = THIS_MODULE,
	.read = vix_devices_read,
	.write = vix_devices_write,
};

static struct vix_dev *vix_find(int id)
{
	struct vix_dev *cur = NULL;

	spin_lock(&lock);
	list_for_each_entry(cur, &vix_dev_list, list) {
		if (cur->id == id) {
			spin_unlock(&lock);
			return cur;
		}
	}
	spin_unlock(&lock);

	return NULL;
}

static ssize_t vix_eject_write(struct file *filp, const char __user *buf, size_t count, loff_t *ppos)
{
	int ret;
	int id;
	struct vix_dev *cur = NULL;

	ret = kstrtoint_from_user(buf, count, 10, &id);

	if (ret < 0)
		return -EINVAL;

	cur = vix_find(id);

	if (cur) {
		spin_lock(&lock);
		list_del(&cur->list);
		spin_unlock(&lock);

		kfree(cur->name);
		kfree(cur);
	} else {
		return -EINVAL;
	}

	ret = count;
	return ret;
}

static const struct file_operations vix_eject_fops = {
	.owner = THIS_MODULE,
	.write = vix_eject_write,
};

static int __init vix_init(void)
{
	dir = debugfs_create_dir(THIS_MODULE->name, NULL);
	if (!dir)
		goto error;

	// Devices and Eject directory setup
	if (!debugfs_create_file("devices", 0600, dir, NULL, &vix_devices_fops))
		goto error;

	if (!debugfs_create_file("eject", 0200, dir, NULL, &vix_eject_fops))
		goto error;

	pr_info("vix: debugfs loaded\n");
	return 0;

error:
	pr_info("vix: debugfs failed to load\n");
	debugfs_remove_recursive(dir);
	return -ENOMEM;
}

static void __exit vix_exit(void)
{
	struct vix_dev *cur = NULL;
	struct vix_dev *tmp = NULL;

	list_for_each_entry_safe(cur, tmp, &vix_dev_list, list) {
		list_del(&cur->list);
		kfree(cur->name);
		kfree(cur);
	}

	debugfs_remove_recursive(dir);
}

module_init(vix_init);
module_exit(vix_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Harry Chong <hjc39@drexel.edu>");
MODULE_DESCRIPTION("HW6 Linked Lists Implementation");
