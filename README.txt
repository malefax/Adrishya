------------------------------------------------------------------------------                  
Introduction                                                                                     
------------------------------------------------------------------------------
Adrishya is a Linux kernel module that leverages advanced kernel hooking tech-
niques,specifically using ftrace (the Linux kernel's function tracer) to hook 
into the mkdir system call. The module is designed to block directory creation 
attempts in a Linux environment by intercepting and modifying the behavior of  
the system call responsible or creating directories. This capability is useful 
for security purposes, such as preventing unauthorized directories from being 
created on a system. The module also demonstrates how kernel hooks, credential 
manipulation, and ftrace-based hooking can be combined for both monitoring and
controlling system behavior in a highly efficient and stealthy manner.

------------------------------------------------------------------------------                  
Aditional Hooks                                                                                     
------------------------------------------------------------------------------
Adrishya also includes hooks into tcp4_seq_show and tcp6_seq_show, enhancing
privacy by hiding network ports from being exposed in /proc/net/tcp and
/proc/net/tcp6. By intercepting these functions, the module prevents unauth-
orized visibility into active network connections, adding an additional layer
of stealth and security.

These hooks are implemented and available in the tcp/ and arm/ branches

=============================================================================
As part of Adrishya, a stealth kernel module project, we implement a privilege
escalation technique by hooking into the Linux syscall of the form:
              SYSCALL_ARCH_PREFIX_sys_getuid
where

    SYSCALL_ARCH_PREFIX∈{__x64,__arm64,…} and SYSCALL_ARCH_PREFIX=∅


This hook allows conditional privilege escalation when a specific environment
variable is detected for example MAGIC=megatron.

These hooks are implemented and available in the main, tcp/, and arm/ branches.

=============================================================================
Adrishya also implements a data stream manipulation technique by hooking into
the Linux splice() system call. This hook intercepts splice — commonly used
for zero-copy file I/O — and applies AES-256-CBC encryption to the data being
transferred. This enables on-the-fly encryption of data streams at the kernel
level, completely hidden from user-space processes, providing stealthy and
secure data handling capabilities.

This hook is implemented and available in the splice/ directory.

------------------------------------------------------------------------------                  
Architecture support                                                                                     
------------------------------------------------------------------------------
Adrishya supports multiple architectures to ensure wide compatibility and
stealth operation across different systems. Currently, the project supports:

  - x86_64 (__x64)
  - ARM64 (__arm64)  — supported via the arm/ branch

Additional architectures may be supported in future releases.

------------------------------------------------------------------------------                  
Hook mkdir POC                                                                               
------------------------------------------------------------------------------


┌─────────────────────────────────────────────────────────────────────────────────┐
│                                 USER SPACE                                      │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│    ┌─────────────┐       mkdir syscall        ┌─────────────┐                   │
│    │ User Program│ ··························>│ VFS Layer   │                   │
│    └─────────────┘                            └─────────────┘                   │
│                                                      │                          │
└──────────────────────────────────────────────────────┼──────────────────────────┘
                                                       │ Call
┌──────────────────────────────────────────────────────┼──────────────────────────┐
│                              KERNEL SPACE            ▼                          │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│                            ┌────────────────────┐                               │
│                            │ __x64_sys_mkdir    │                               │
│                            └─────────┬──────────┘                               │
│                                      │                                          │
│              ┌───────────────────────┼───────────────────────┐                  │
│              │                       │                       │                  │
│              ▼                       ▼                       │                  │
│    ┌─────────────────┐    ┌─────────────────────┐            │                  │
│    │ NORMAL FLOW     │    │ HOOKED FLOW         │            │                  │
│    │                 │    │                     │            │                  │
│    │ ┌─────────────┐ │    │ ┌─────────────────┐ │            │                  │
│    │ │Regular mkdir│ │    │ │   hook_mkdir    │ │            │                  │
│    │ │ processing  │ │    │ └─────────┬───────┘ │            │                  │
│    │ └─────┬───────┘ │    │           │ 1       │            │                  │
│    │       │         │    │           ▼         │            │                  │
│    │       ▼         │    │ ┌─────────────────┐ │            │                  │
│    │ ┌─────────────┐ │    │ │Copy Path from   │ │            │                  │
│    │ │ Directory   │ │    │ │User Space       │ │            │                  │
│    │ │ Created     │ │    │ └─────────┬───────┘ │            │                  │
│    │ └─────────────┘ │    │           │ 2       │            │                  │
│    └─────────────────┘    │           ▼         │            │                  │
│                           │ ┌─────────────────┐ │            │                  │
│                           │ │  Log Attempt    │ │            │                  │
│                           │ └─────────┬───────┘ │            │                  │
│                           │           │ 3       │            │                  │
│                           │           ▼         │            │                  │
│                           │ ┌─────────────────┐ │            │                  │
│                           │ │Return -EACCES   │ │            │                  │
│                           │ │Block Creation   │ │            │                  │
│                           │ └─────────────────┘ │            │                  │
│                           └─────────────────────┘            │                  │
│                                                              │                  │
│    ┌─────────────────────────────────────────────────────────┘                  │
│    │ HOOK INSTALLATION                                                          │
│    │                                                                            │
│    │ ┌──────────────┐  1   ┌─────────────────────┐  2   ┌─────────────────┐     │
│    │ │ Module Load  │ ───> │ Resolve             │ ───> │ Setup ftrace    │     │
│    │ └──────────────┘      │ __x64_sys_mkdir     │      │ ops             │     │
│    │                       │ Address             │      └─────────┬───────┘     │
│    │                       └─────────────────────┘                │ 3           │
│    │                                                              ▼             │
│    │                       ┌─────────────────────┐      ┌─────────────────┐     │
│    │                       │   hook_mkdir        │ <────│ Install Hook    │     │
│    │                       └─────────────────────┘  4   └─────────────────┘     │
│    └────────────────────────────────────────────────────────────────────────────│
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
===================================================================================
Installation
-----------------------------------------------------------------------------------

$ git clone https://github.com/malefax/Adrishya.git

$ cd Adrishya/

$ sudo make

$ ls 

Adrishya.c   Adrishya.mod    Adrishya.mod.o  Makefile       Module.symvers
Adrishya.ko  Adrishya.mod.c  Adrishya.o      modules.order  secure.h

$ sudo insmod Adrishya.ko

===================================================================================
Example
-----------------------------------------------------------------------------------
$ MAGIC=megatron bash

$ whoami 
root

$ mkdir test

No directory is actually created during this process!
===================================================================================











