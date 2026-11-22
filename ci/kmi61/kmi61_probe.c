// SPDX-License-Identifier: GPL-2.0-only
/*
 * kmi61_probe - minimal external module built against the Android 6.1 DDK.
 *
 * Its only job is to carry a real, cross-KMI `struct module` layout in
 * `.gnu.linkonce.this_module` and a 6.1 vermagic, so lkmctl-android has to
 * adapt both before the 6.12 device kernel will accept it.
 */
#include <linux/kernel.h>
#include <linux/module.h>

static int __init kmi61_probe_init(void)
{
	pr_info("kmi61_probe: init\n");
	return 0;
}

static void __exit kmi61_probe_exit(void)
{
	pr_info("kmi61_probe: exit\n");
}

module_init(kmi61_probe_init);
module_exit(kmi61_probe_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("droid-lkm-ins KMI 6.1 struct-module layout probe");
