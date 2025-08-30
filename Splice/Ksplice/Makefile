# Makefile for a simple Linux Kernel Module

# Define the kernel source directory and module name
KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
MODULE_NAME := Adrishya

# Specify object files
obj-m := $(MODULE_NAME).o

# Check if the architecture is x86
ARCH := $(shell uname -m)
ifneq ($(ARCH), x86_64)
  $(error This Makefile is only for x86_64 architecture. Detected architecture: $(ARCH))
endif

# Default target
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

# Clean up generated files
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

# Remove module
remove:
	sudo rmmod $(MODULE_NAME)

.PHONY: all clean remove

