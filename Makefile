#
#Makefile for a simple Linux Kernel Module

# Define the kernel source directory and module name
KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
MODULE_NAME := Adrishya2

# Specify object files
obj-m := $(MODULE_NAME).o

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
