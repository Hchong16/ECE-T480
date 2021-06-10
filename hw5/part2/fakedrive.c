// SPDX-License-Identifier: GPL-2.0
// Author: Harry Chong (Student ID: 14158124)
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>

#define USER_ID "14158124"
#define BUFFER_SIZE 1024
static char buffer[BUFFER_SIZE];

static int fakedrive_open(struct inode *inode, struct file *filp)
{
	return 0;
}

static int fakedrive_release(struct inode *inode, struct file *filp)
{
	return 0;
}

static ssize_t fakedrive_read(struct file *filp, char __user *buf,
		size_t size, loff_t *offset)
{
	int ret;

	ret = simple_read_from_buffer(buf, size, offset, USER_ID, strlen(USER_ID));

	//pr_info("fakedrive: read %d bytes\n", ret);

	return ret;
}

static ssize_t fakedrive_write(struct file *filp, const char __user *buf,
		size_t size, loff_t *offset)
{
	int ret;

	memset(&buffer, 0, BUFFER_SIZE); // Clear buffer

	ret = simple_write_to_buffer(buffer, sizeof(buffer), offset, buf, size);

	//pr_info("fakedrive: write %d bytes\n", ret);
	//pr_info("fakedrive (TEST): %s\n", buffer);
	//pr_info("fakedrive (SIZE): %zu\n", strlen(buffer));
	//pr_info("fakedrive (COMPARE STATUS): %d\n", strcmp(buffer, USER_ID));

	if (strcmp(buffer, USER_ID) == 0) {
		pr_info("fakedrive: initialized\n");
		return ret;
	}

	pr_info("fakedrive: initialization failed\n");
	return -EINVAL;
}

static const struct file_operations fops = {
	.owner = THIS_MODULE,
	.read = fakedrive_read,
	.write = fakedrive_write,
	.open = fakedrive_open,
	.release = fakedrive_release,
};

static struct miscdevice fakedrive_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "fakedrive",
	.fops = &fops,
};

static int __init fakedrive_init(void)
{
	int ret;

	pr_info("Module %s loaded\n", THIS_MODULE->name);

	ret = misc_register(&fakedrive_device);
	if (ret)
		pr_info("fakedrive: misc_register() failed\n");
	else
		pr_info("fakedrive: misc device successfully registered\n");

	return ret;
}

static void __exit fakedrive_exit(void)
{
	misc_deregister(&fakedrive_device);
	pr_info("fakedrive: misc device module successfully unloaded\n");
}

module_init(fakedrive_init);
module_exit(fakedrive_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Harry Chong");
MODULE_DESCRIPTION("Simple kernel module that implements a misc device.");
