#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/elfnote-lto.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;
BUILD_LTO_INFO;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif

static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0x6ad771c3, "module_layout" },
	{ 0xa5a1793e, "unregister_ftrace_function" },
	{ 0x90de72a9, "register_ftrace_function" },
	{ 0x6f935e35, "ftrace_set_filter_ip" },
	{ 0xa3b6c0d8, "kobject_del" },
	{ 0x97e2789a, "commit_creds" },
	{ 0x11bab86, "prepare_creds" },
	{ 0x63026490, "unregister_kprobe" },
	{ 0xfcca5424, "register_kprobe" },
	{ 0x92997ed8, "_printk" },
	{ 0xd0da656b, "__stack_chk_fail" },
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0x8522d6bc, "strncpy_from_user" },
	{ 0xbdfb6dbb, "__fentry__" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "1D0D87A425086251A38257B");
