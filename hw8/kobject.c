// SPDX-License-Identifier: GPL-2.0
#include <linux/kobject.h>
#include <linux/string.h>
#include <linux/sysfs.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/init.h>

struct fakedrive {
	unsigned long capacity;
	const char *model;
	const char *rev;
	struct kobject kobj;
	int powersave;
};

struct kmem_cache *fakedrive_cache;

struct fakedrive_attribute {
	struct attribute attr;
	ssize_t (*show)(struct fakedrive *fakedrive, struct fakedrive_attribute *attr, char *buf);
	ssize_t (*store)(struct fakedrive *fakedrive, struct fakedrive_attribute *attr, const char *buf, size_t count);
};

static ssize_t fakedrive_attr_show(struct kobject *kobj,
			     struct attribute *attr,
			     char *buf)
{
	struct fakedrive_attribute *attribute;
	struct fakedrive *fakedrive;

	attribute = container_of(attr, struct fakedrive_attribute, attr);
	fakedrive = container_of(kobj, struct fakedrive, kobj);

	if (!attribute->show)
		return -EIO;

	return attribute->show(fakedrive, attribute, buf);
}

static ssize_t fakedrive_attr_store(struct kobject *kobj, struct attribute *attr, const char *buf, size_t len)
{
	struct fakedrive_attribute *attribute;
	struct fakedrive *fakedrive;

	attribute = container_of(attr, struct fakedrive_attribute, attr);
	fakedrive = container_of(kobj, struct fakedrive, kobj);

	if (!attribute->store)
		return -EIO;

	return attribute->store(fakedrive, attribute, buf, len);
}

static const struct sysfs_ops fakedrive_sysfs_ops = {
	.show = fakedrive_attr_show,
	.store = fakedrive_attr_store,
};

static void fakedrive_release(struct kobject *kobj)
{
	struct fakedrive *fakedrive;

	fakedrive = container_of(kobj, struct fakedrive, kobj);
}

static ssize_t info_show(struct fakedrive *fakedrive, struct fakedrive_attribute *attr, char *buf)
{
	unsigned long val;
	const char *string;

	if (strcmp(attr->attr.name, "capacity") == 0) {
		val = fakedrive->capacity;
		return sprintf(buf, "%lu\n", val);
	} else if (strcmp(attr->attr.name, "model") == 0) {
		string = fakedrive->model;
		return sprintf(buf, "%s\n", string);
	} else if (strcmp(attr->attr.name, "rev") == 0) {
		string = fakedrive->rev;
		return sprintf(buf, "%s\n", string);
	}

	return -EINVAL;
}

static ssize_t info_store(struct fakedrive *fakedrive, struct fakedrive_attribute *attr,
	const char *buf, size_t count)
{
	return 0;
}

static struct fakedrive_attribute capacity_attribute =
	__ATTR(capacity, 0444, info_show, info_store);
static struct fakedrive_attribute model_attribute =
	__ATTR(model, 0444, info_show, info_store);
static struct fakedrive_attribute rev_attribute =
	__ATTR(rev, 0444, info_show, info_store);

static ssize_t power_show(struct fakedrive *fakedrive, struct fakedrive_attribute *attr, char *buf)
{
	int val;

	val = fakedrive->powersave;

	return sprintf(buf, "%d\n", val);
}

static ssize_t power_store(struct fakedrive *fakedrive, struct fakedrive_attribute *attr,
	const char *buf, size_t count)
{
	int val, ret;

	ret = kstrtoint(buf, 10, &val);
	if (ret < 0)
		return ret;

	if (val == 0 || val == 1) {
		fakedrive->powersave = val;
		return count;
	}

	return -EINVAL;
}

static struct fakedrive_attribute power_attribute =
	__ATTR(powersave, 0664, power_show, power_store);

/* Info Attribute Group */
static struct attribute *fakedrive_info_attrs[] = {
	&capacity_attribute.attr,
	&model_attribute.attr,
	&rev_attribute.attr,
	NULL,
};

static struct attribute_group fakedrive_info_group = {
	.name = "info",
	.attrs = fakedrive_info_attrs
};

/* Powersave Attribute */
static struct attribute *fakedrive_power_attrs[] = {
	&power_attribute.attr,
	NULL,
};

static struct attribute_group fakedrive_power_group = {
	.name = NULL,
	.attrs = fakedrive_power_attrs
};

/* Merge Attributes to one group */
static const struct attribute_group *fakedrive_attribute_groups[] = {
	&fakedrive_info_group,
	&fakedrive_power_group,
	NULL,
};

static struct kobj_type fakedrive_ktype = {
	.sysfs_ops = &fakedrive_sysfs_ops,
	.release = fakedrive_release,
	.default_groups = fakedrive_attribute_groups,
};

static struct kset *fakedrive_kset;
static struct fakedrive *device0;
static struct fakedrive *device1;
static struct fakedrive *device2;
static struct fakedrive *device3;

static struct fakedrive *create_fakedrive(const char *name)
{
	struct fakedrive *fakedrive;
	int ret;

	fakedrive = kmem_cache_zalloc(fakedrive_cache, GFP_KERNEL);
	if (!fakedrive)
		return NULL;

	fakedrive->kobj.kset = fakedrive_kset;

	ret = kobject_init_and_add(&fakedrive->kobj, &fakedrive_ktype, NULL, "%s", name);
	if (ret) {
		kobject_put(&fakedrive->kobj);
		return NULL;
	}

	kobject_uevent(&fakedrive->kobj, KOBJ_ADD);

	return fakedrive;
}

static void destroy_fakedrive(struct fakedrive *fakedrive)
{
	kobject_put(&fakedrive->kobj);
}

static int __init fakedrive_init(void)
{
	fakedrive_cache = KMEM_CACHE(fakedrive, 0);
	fakedrive_kset = kset_create_and_add("fakedrive", NULL, kernel_kobj);

	device0 = create_fakedrive("device0");
	if (!device0)
		goto device0_error;
	else {
		device0->capacity = 1922320888;
		device0->model = "Samsung EVO SSD";
		device0->rev = "e7va";
		device0->powersave = 0;
	}

	device1 = create_fakedrive("device1");
	if (!device1)
		goto device1_error;
	else {
		device1->capacity = 2884153776;
		device1->model = "Western Digital Green HD";
		device1->rev = "wd3922123b";
		device1->powersave = 1;
	}

	device2 = create_fakedrive("device2");
	if (!device2)
		goto device2_error;
	else {
		device2->capacity = 229701780;
		device2->model = "Crucial SSD";
		device2->rev = "sg41";
		device2->powersave = 1;
	}

	device3 = create_fakedrive("device3");
	if (!device3)
		goto device3_error;
	else {
		device3->capacity = 205937544;
		device3->model = "Samsung EVO NVMe";
		device3->rev = "e9nv1";
		device3->powersave = 0;
	}

	return 0;

device3_error:
	destroy_fakedrive(device2);
device2_error:
	destroy_fakedrive(device1);
device1_error:
	destroy_fakedrive(device0);
device0_error:
	kset_unregister(fakedrive_kset);

	return -EINVAL;
}

static void __exit fakedrive_exit(void)
{
	struct kobject *entry, *sav;

	list_for_each_entry_safe(entry, sav, &fakedrive_kset->list, entry) {
		kobject_put(entry);
	}

	kset_unregister(fakedrive_kset);

	kmem_cache_free(fakedrive_cache, device3);
	kmem_cache_free(fakedrive_cache, device2);
	kmem_cache_free(fakedrive_cache, device1);
	kmem_cache_free(fakedrive_cache, device0);
	kmem_cache_destroy(fakedrive_cache);
}

module_init(fakedrive_init);
module_exit(fakedrive_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Harry Chong <hjc39@drexel.edu>");
MODULE_DESCRIPTION("HW8 Implementation");
