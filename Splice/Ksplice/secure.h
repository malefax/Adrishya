#ifndef __SECURE__h
#define __SECURE__h

/*
 * Macro to validate that a function pointer matches a specific signature.
 * Usage: DECL_FUNC_CHECK(your_func_ptr, expected_signature)
 * Life before c11 introduced-_-   
 */
#define DECL_FUNC_CHECK(ptr, signature) \
    _Static_assert( \
        __builtin_types_compatible_p(__typeof__(ptr), signature), \
        "Error: Function pointer '" #ptr "' does not match expected signature '" #signature "'." \
    )

/*
 * Signature definitions — trusted syscall function pointer types
 * Add new ones here as needed
 * But Unique function signature!-__-!
 */
#define SIG_GET_PID         long (*)(const struct pt_regs *)
#define SIG_SPLICE         long (*)(const struct pt_regs *)
/*
 * Example usage:
 * typedef asmlinkage long (*my_tcp4_hook)(struct seq_file *seq, void *v);
 * DECL_FUNC_CHECK(my_tcp4_hook, SIG_SEQ_SHOW);
 */

#endif // SECURE

