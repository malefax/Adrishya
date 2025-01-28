# Adrishya(अदृश्य)
![SHIV](https://img.freepik.com/premium-photo/black-lord-shiva-special-maha-shivaratri-made-using-generative-ai-tools_410516-74403.jpg)

## Introduction
**Adrishya is a Linux kernel module that leverages advanced kernel hooking techniques, specifically using ftrace (the Linux kernel's function tracer) to hook into the mkdir system call. The module is designed to block directory creation attempts in a Linux environment by intercepting and modifying the behavior of the system call responsible for creating directories. This capability is useful for security purposes, such as preventing unauthorized directories from being created on a system.
The module also demonstrates how kernel hooks, credential manipulation, and ftrace-based hooking can be combined for both monitoring and controlling system behavior in a highly efficient and stealthy manner.**<br>

```mermaid

   flowchart TD
    subgraph "User Space"
        A[User Program] -..->|mkdir syscall| B[VFS Layer]
    end

    subgraph "Kernel Space"
        B -..->|Call| C["__x64_sys_mkdir"]
        
        subgraph "Normal Flow"
            C -->|Original Call| D[Regular mkdir\nprocessing]
            D -->|Success| E[Directory Created]
        end
        
        subgraph "Hooked Flow"
            C -.->|Intercept| F["hook_mkdir"]
            F -->|1| G[Copy Path from\nUser Space]
            G -->|2| H[Log Attempt]
            H -.->|3| I[Return -EACCES\nBlock Creation]
        end
    end

    subgraph "Hook Installation"
        K[Module Load] -.->|1| L[Resolve\n__x64_sys_mkdir\nAddress]
        L -.->|2| M[Setup ftrace ops]
        M -.->|3| N[Install Hook]
        N -.->|4| F
    end

    classDef userspace fill:#f9f,stroke:#333,stroke-width:2px;
    classDef kernel fill:#bbf,stroke:#333,stroke-width:2px;
    classDef hook fill:#fda,stroke:#333,stroke-width:2px;
    classDef block fill:#faa,stroke:#333,stroke-width:2px;
    classDef installation fill:#dfd,stroke:#333,stroke-width:2px;

    class A userspace;
    class B,C,D kernel;
    class F,G hook;
    class I block;
    class K,L,M,N installation;
```

## Caution
**only work for x86_64**<br>
**To check architecture of linux os type**<br>
```uname -m```<br>
## Installation

![hackerman](https://media1.tenor.com/images/05729f2e534ba37254f95b39e9647d29/tenor.gif?itemid=3552791)

**1.clone the repository**<br>
```git clone -b tcp  https://github.com/malefax/Adrishya.git```

**2. navigate the directory**<br>
```cd Adrishya/```

**3. To enable hooks change value 0->1 in macros on Adrishya2.c**<br>

```c
#define TCP_HOOK_IS_ENABLED 1
#define MKDIR_HOOK_IS_ENABLED 1
```
**4 To disable hook change the value 1->0 in macros on Adrishya2.c**
  ```c
  #define TCP_HOOK_IS_ENABLED 0
  #define MKDIR_HOOK_IS_ENABLED 0
  ```
**6. By default both is enabled**

**7. generate required files by**<br>
```sudo make```<br>

## Uses
**1. Before inserting batchfile**<br>

![before.png](before.png)

**2.After inserting batchfile**<br>
**3.To inserting batch file **<br>

```sudo insmod Adrishya2.ko```<br>

![after.png](after.png)


