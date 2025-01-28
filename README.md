# Adrishya(अदृश्य)
![SHIV](https://img.freepik.com/premium-photo/black-lord-shiva-special-maha-%20shivaratri-made-using-generative-ai-tools_410516-74403.jpg)
## Introduction
**Adrishya is a Linux kernel module that leverages advanced kernel hooking techniques, specifically using ftrace (the Linux kernel's function tracer) to hook into the mkdir system call. The module is designed to block directory creation attempts in a Linux environment by intercepting and modifying the behavior of the system call responsible for creating directories. This capability is useful for security purposes, such as preventing unauthorized directories from being created on a system.
The module also demonstrates how kernel hooks, credential manipulation, and ftrace-based hooking can be combined for both monitoring and controlling system behavior in a highly efficient and stealthy manner.**<br>
## NOTE 
For the latest version of the project, please switch to the `tcp` branch.
## Hook mkdir POC
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

    classDef userspace fill:#f9f,stroke:#333,stroke-width:2px,color:#000;
    classDef kernel fill:#bbf,stroke:#333,stroke-width:2px,color:#000;
    classDef hook fill:#fda,stroke:#333,stroke-width:2px,color:#000;
    classDef block fill:#faa,stroke:#333,stroke-width:2px,color:#000;
    classDef installation fill:#dfd,stroke:#333,stroke-width:2px,color:#000;

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

**check for sycall**<br>
``` cat /proc/kallsyms | grep sys_mkdir```<br>

**in my case**<br>
**ffffffff90babf40 T __x64_sys_mkdir**<br>


## Installation

**1.clone the repository**<br>
```git clone https://github.com/malefax/Adrishya.git```

**2. navigate the directory**<br>
```cd Adrishya/```

**3. generate required files by**<br>
```sudo make```

## Uses
**insert the batchfile by**<br>
```sudo insmod Adrishya.ko```<br>

**now try to make directory in new bash session**<br>
```mkdir test```<br>

## Result
**mkdir: cannot create directory ‘test’: Permission denied**<br>

![result](https://i.pinimg.com/originals/17/f4/cd/17f4cd781dbae9d737e117ac64e101ce.gif)

## Status
```dmesg | tail -n 5```<br>
**[ 5195.072954] mkdir_monitor: Loaded**<br>
**[ 5215.531106] Directory creation blocked: test**<br>

**Check out my blog post about the project:** [here](https://medium.com/@_._.._/mkdir-api-hook-a-pathway-to-an-lkm-rootkit-in-linux-ae5e3fa6d4b8)

