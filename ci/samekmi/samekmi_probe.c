// SPDX-License-Identifier: GPL-2.0-only
/*
 * samekmi_probe - a minimal module built against the same KMI's DDK tree as
 * the kernel it is loaded on (android16-6.12).
 *
 * The QEMU gate uses it to prove the layout adaptation: the .ko is built
 * normally (matching vermagic, matching CFI instrumentation), then a
 * reproducible script moves its .gnu.linkonce.this_module sh_size and its
 * init/exit relocations to a second known set.  lkmctl must adapt them back
 * before init_module(2) will accept the image.
 */
#include <linux/kernel.h>
#include <linux/module.h>

static int __init samekmi_probe_init(void)
{
	pr_info("samekmi_probe: init\n");
	return 0;
}

static void __exit samekmi_probe_exit(void)
{
	pr_info("samekmi_probe: exit\n");
}

module_init(samekmi_probe_init);
module_exit(samekmi_probe_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("droid-lkm-ins same-KMI layout-adaptation probe");
