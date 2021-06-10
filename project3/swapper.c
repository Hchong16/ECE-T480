// SPDX-License-Identifier: GPL-2.0
#include <linux/kobject.h>
#include <linux/string.h>
#include <linux/sysfs.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/debugfs.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/list.h>

#define BUFFER_SIZE 4096
static DEFINE_SPINLOCK(lock);
static DEFINE_MUTEX(mlock);

static LIST_HEAD(swapper_dev_list);
static struct dentry *dir;
static char *last_name = "default";
static int status; // Open Count: 0 (Open) and 1 (Close)

/*=========================swapstore object============================*/
struct swapstore {
	struct kobject kobj;
	char data[BUFFER_SIZE];
	char *name;
	int readonly;
	int removable;

	int eject; // Variable to track removal kobj in the case it is "active"
};

struct swapstore_attribute {
	struct attribute attr;

	ssize_t (*show)(struct swapstore *swapstore,
			struct swapstore_attribute *attr,
			char *buf);

	ssize_t (*store)(struct swapstore *swapstore,
			struct swapstore_attribute *attr,
			const char *buf, size_t count);
};

static ssize_t swapstore_attr_show(struct kobject *kobj,
			     struct attribute *attr,
			     char *buf)
{
	struct swapstore_attribute *attribute;
	struct swapstore *swapstore;

	attribute = container_of(attr, struct swapstore_attribute, attr);
	swapstore = container_of(kobj, struct swapstore, kobj);

	if (!attribute->show)
		return -EIO;

	return attribute->show(swapstore, attribute, buf);
}

static ssize_t swapstore_attr_store(struct kobject *kobj, struct attribute *attr,
		const char *buf, size_t len)
{
	struct swapstore_attribute *attribute;
	struct swapstore *swapstore;

	attribute = container_of(attr, struct swapstore_attribute, attr);
	swapstore = container_of(kobj, struct swapstore, kobj);

	if (!attribute->store)
		return -EIO;

	return attribute->store(swapstore, attribute, buf, len);
}

static const struct sysfs_ops swapstore_sysfs_ops = {
	.show = swapstore_attr_show,
	.store = swapstore_attr_store,
};

static void swapstore_release(struct kobject *kobj)
{
	struct swapstore *swapstore;

	swapstore = container_of(kobj, struct swapstore, kobj);
	kfree(swapstore);
}

static ssize_t main_show(struct swapstore *swapstore, struct swapstore_attribute *attr, char *buf)
{
	int val;

	if (strcmp(attr->attr.name, "readonly") == 0) {
		val = swapstore->readonly;
		return sprintf(buf, "%d\n", val);
	} else if (strcmp(attr->attr.name, "removable") == 0) {
		val = swapstore->removable;
		return sprintf(buf, "%d\n", val);
	}

	return -EINVAL;
}

static ssize_t main_store(struct swapstore *swapstore, struct swapstore_attribute *attr,
	const char *buf, size_t count)
{
	int val, ret;

	if (strcmp(attr->attr.name, "removable") == 0)
		return -EPERM;

	ret = kstrtoint(buf, 10, &val);
	if (ret < 0)
		return ret;

	if (val == 0 || val == 1) {
		if (strcmp(attr->attr.name, "readonly") == 0) {
			swapstore->readonly = val;
			return count;
		}
	}

	return -EINVAL;
}

static struct swapstore_attribute readonly_attribute =
	__ATTR(readonly, 0600, main_show, main_store);
static struct swapstore_attribute removable_attribute =
	__ATTR(removable, 0400, main_show, main_store);

/* Info Attribute Group */
static struct attribute *swapstore_default_attrs[] = {
	&removable_attribute.attr,
	&readonly_attribute.attr,
	NULL,
};
ATTRIBUTE_GROUPS(swapstore_default);

static struct kobj_type swapstore_ktype = {
	.sysfs_ops = &swapstore_sysfs_ops,
	.release = swapstore_release,
	.default_groups = swapstore_default_groups,
};

static struct kset *swapstore_kset;
static struct swapstore *default0;

static struct swapstore *create_swapstore(char *name)
{
	struct swapstore *swapstore;
	int ret;

	swapstore = kzalloc(sizeof(*swapstore), GFP_KERNEL);
	if (!swapstore)
		return NULL;

	swapstore->kobj.kset = swapstore_kset;
	swapstore->name = name;

	ret = kobject_init_and_add(&swapstore->kobj, &swapstore_ktype, NULL, "%s", name);
	if (ret) {
		kobject_put(&swapstore->kobj);
		return NULL;
	}

	kobject_uevent(&swapstore->kobj, KOBJ_ADD);

	return swapstore;
}

static void destroy_swapstore(struct swapstore *swapstore)
{
	kobject_put(&swapstore->kobj);
}

/*============================debugfs interface=================================*/
struct swapper_dev {
	char *name;
	struct swapstore *swapstore_obj;

	struct list_head list;
};

static struct swapper_dev *swapper_find(char *name)
{
	struct swapper_dev *cur = NULL;

	spin_lock(&lock);
	list_for_each_entry(cur, &swapper_dev_list, list) {
		if (strcmp(cur->name, name) == 0) {
			spin_unlock(&lock);
			return cur;
		}
	}
	spin_unlock(&lock);

	return NULL;
}

static ssize_t swapper_insert_write(struct file *filp, const char __user *buf,
		size_t count, loff_t *ppos)
{
	int ret;
	struct swapstore *swapstore_obj;
	struct swapper_dev *cur = NULL;
	struct swapper_dev *dev = kmalloc(sizeof(*dev), GFP_KERNEL);

	if (!dev)
		return -ENOMEM;

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

	// Check for existing swapstore name
	cur = swapper_find(dev->name);
	if (cur)
		return -EINVAL;

	// Create kobj and swapper_dev
	swapstore_obj = create_swapstore(dev->name);
	if (!swapstore_obj)
		return -EINVAL;

	swapstore_obj->removable = 1;
	swapstore_obj->readonly = 0;

	// Assign swapstore_obj to swapper_dev
	dev->swapstore_obj = swapstore_obj;

	spin_lock(&lock);
	list_add_tail(&dev->list, &swapper_dev_list);
	spin_unlock(&lock);

	return ret;
}

static const struct file_operations swapper_insert_fops = {
	.owner = THIS_MODULE,
	.write = swapper_insert_write,
};

static ssize_t swapper_eject_write(struct file *filp, const char __user *buf,
		size_t count, loff_t *ppos)
{
	int ret;
	char *name;
	struct swapper_dev *cur = NULL;

	name = kmalloc(sizeof(char) * (count+1), GFP_KERNEL);

	ret = simple_write_to_buffer(name, count, ppos, buf, count);
	if (ret < 0)
		return -EINVAL;

	name[ret] = '\0'; // Add null terminator

	// Default Case
	if (strcmp(name, "default") == 0) {
		pr_info("device default is not removable\n");
		return -EINVAL;
	}

	cur = swapper_find(name);

	if (cur) {
		spin_lock(&lock);

		if (cur->swapstore_obj->removable == 0) {
			spin_unlock(&lock);
			return -EINVAL;
		}

		pr_info("releasing %s\n", name);

		 // Active swapstore, change eject to 1 and handle removal in swapstore_write fops
		if (strcmp(last_name, name) == 0) {
			cur->swapstore_obj->eject = 1;
			spin_unlock(&lock);
			return ret;
		}

		list_del(&cur->list);
		destroy_swapstore(cur->swapstore_obj);
		spin_unlock(&lock);

		kfree(cur->name);
		kfree(cur);
	} else {
		return -EINVAL;
	}

	ret = count;
	return ret;
}

static const struct file_operations swapper_eject_fops = {
	.owner = THIS_MODULE,
	.write = swapper_eject_write,
};

static ssize_t swapper_swapstore_write(struct file *filp, const char __user *buf,
		size_t count, loff_t *ppos)
{
	int ret;
	char *name;
	struct swapper_dev *cur = NULL;

	// Before changing last_name, remove release device if eject is 1
	cur = swapper_find(last_name);

	if (cur) {
		if (strcmp(last_name, cur->swapstore_obj->name) == 0 && cur->swapstore_obj->removable == 1) {
			if (cur->swapstore_obj->eject == 1) {
				spin_lock(&lock);
				list_del(&cur->list);
				destroy_swapstore(cur->swapstore_obj);
				spin_unlock(&lock);

				kfree(cur->name);
				kfree(cur);
			}
		}
	}

	if (status == 0) {
		name = kmalloc(sizeof(char) * (count+1), GFP_KERNEL);

		ret = simple_write_to_buffer(name, count, ppos, buf, count);
		if (ret < 0)
			return -EINVAL;

		name[ret] = '\0'; // Add null terminator

		if (strcmp(name, last_name) == 0) {
			mutex_lock(&mlock);
			last_name = "default";
			mutex_unlock(&mlock);
		} else {
			mutex_lock(&mlock);
			last_name = name;
			mutex_unlock(&mlock);
		}
	} else {
		return -EBUSY;
	}

	ret = count;
	return ret;
}

static const struct file_operations swapper_swapstore_fops = {
	.owner = THIS_MODULE,
	.write = swapper_swapstore_write,
};

/*============================misc device=================================*/
static int swapper_open(struct inode *inode, struct file *filp)
{
	mutex_lock(&mlock);
	pr_info("open count: 1\n");
	status = 1;
	mutex_unlock(&mlock);
	return 0;
}

static int swapper_release(struct inode *inode, struct file *filp)
{
	mutex_lock(&mlock);
	pr_info("open count: 0\n");
	status = 0;
	mutex_unlock(&mlock);
	return 0;
}

static ssize_t swapper_read(struct file *filp, char __user *buf,
		size_t count, loff_t *ppos)
{
	int ret;
	struct swapper_dev *cur = NULL;

	// Base case for Default
	if (strcmp(last_name, "default") == 0) {
		ret = simple_read_from_buffer(buf, count, ppos, default0->data, BUFFER_SIZE);
		return ret;
	}

	cur = swapper_find(last_name);
	if (cur) {
		ret = simple_read_from_buffer(buf, count, ppos, cur->swapstore_obj->data, BUFFER_SIZE);
		return ret;
	}

	return ret;
}

static ssize_t swapper_write(struct file *filp, const char __user *buf,
		size_t count, loff_t *ppos)
{
	int ret;
	struct swapper_dev *cur = NULL;

	// Base case for Default
	if (strcmp(last_name, "default") == 0) {
		memset(default0->data, 0, BUFFER_SIZE); // Clear buffer

		if (default0->readonly == 1) {
			pr_info("%s device is readonly\n", last_name);
			return -EPERM;
		}

		// Write value to buffer
		ret = simple_write_to_buffer(default0->data, BUFFER_SIZE, ppos, buf, count);
		if (ret < 0)
			return -EINVAL;

		default0->data[ret] = '\0'; // Add null terminator
	} else {
		cur = swapper_find(last_name);

		if (cur) {
			if (cur->swapstore_obj->readonly == 1)
				return -EPERM;

			memset(&cur->swapstore_obj->data, 0, BUFFER_SIZE); // Clear buffer

			// Write value to buffer
			ret = simple_write_to_buffer(cur->swapstore_obj->data, BUFFER_SIZE, ppos, buf, count);
			if (ret < 0)
				return -EINVAL;

			cur->swapstore_obj->data[ret] = '\0'; // Add null terminator
		} else {
			return -EINVAL;
		}
	}

	ret = count;
	return ret;
}

static const struct file_operations swapper_fops = {
	.owner = THIS_MODULE,
	.read = swapper_read,
	.write = swapper_write,
	.open = swapper_open,
	.release = swapper_release,
};

static struct miscdevice swapper_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "swapper",
	.fops = &swapper_fops,
};

/*============================module setup=================================*/
static int __init swapper_init(void)
{
	int ret;
	struct swapper_dev *dev = kmalloc(sizeof(*dev), GFP_KERNEL);

	// Setup kobject and kset
	swapstore_kset = kset_create_and_add("swapstore", NULL, kernel_kobj);
	if (!swapstore_kset)
		return -ENOMEM;

	default0 = create_swapstore("default");
	if (!default0)
		goto default0_error;
	else {
		default0->removable = 0;
		default0->readonly = 0;
	}

	if (!dev)
		return -ENOMEM;

	// Setup debugfs interface
	dir = debugfs_create_dir(THIS_MODULE->name, NULL);
	if (!dir)
		goto debugfs_error;

	if (!debugfs_create_file("insert", 0200, dir, NULL, &swapper_insert_fops))
		goto debugfs_error;

	if (!debugfs_create_file("eject", 0200, dir, NULL, &swapper_eject_fops))
		goto debugfs_error;

	if (!debugfs_create_file("swapstore", 0600, dir, NULL, &swapper_swapstore_fops))
		goto debugfs_error;

	// Setup misc device
	ret = misc_register(&swapper_device);

	return 0;

default0_error:
	kset_unregister(swapstore_kset);
	return -EINVAL;
debugfs_error:
	pr_info("swapper: debugfs failed to load\n");
	debugfs_remove_recursive(dir);
	return -ENOMEM;
}

static void __exit swapper_exit(void)
{
	struct kobject *entry, *sav;
	struct swapper_dev *cur = NULL;
	struct swapper_dev *tmp = NULL;

	// Unload kobject and kset
	list_for_each_entry_safe(entry, sav, &swapstore_kset->list, entry) {
		kobject_put(entry);
	}

	kset_unregister(swapstore_kset);

	// Unload debugfs interface
	list_for_each_entry_safe(cur, tmp, &swapper_dev_list, list) {
		list_del(&cur->list);
		kfree(cur->name);
		kfree(cur);
	}

	debugfs_remove_recursive(dir);

	// Unload misc device
	misc_deregister(&swapper_device);

	pr_info("swapper: clean complete\n");
}

module_init(swapper_init);
module_exit(swapper_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Harry Chong <hjc39@drexel.edu>");
MODULE_DESCRIPTION("Project 3");
