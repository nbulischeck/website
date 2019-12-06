---
layout: post
title: Introduction to Kernel Module Development
categories: linux
date: 2018-04-25 22:00:00 +0300
description: An introduction to programming loadable kernel modules
tags: [linux, kernel, c]
---

## Introduction

This post will serve as an introduction to those wanting to get into the development of loadable kernel modules. Loadable kernel modules, LKMs for short, are an integral companion to the Linux kernel. Imagine the Linux kernel as a giant robot. Let's say that this giant robot is already amazing as is, but you want to upgrade it with your own custom flamethrower. You'd have to first build your flamethrower and then attach it to the giant robot. You may not have helped build the giant robot, but you added some additional functionality to it. It runs the same way it did before, but now it's even better! This is exactly the same scenario for LKMs. Intuitively, when your giant robot's flamethrower is no longer needed (he or she is a pacifist now), it can be safely removed in order to free up space.

Typically, LKMs are used to add support for new hardware (as device drivers) or filesystems, or add additional system calls. Without LKMs, an operating system would have to include all possible anticipated functionality. This is borderline impossible to do when developing a platform to be used with everything from a smartphone to a server.

In summary, LKMs provide additional functionality to the kernel, and by extension the user of the computer, and can be safely added or removed when they are needed or not needed.

## LKM Development

I'm making the assumption that most users have a competent grasp on the C language and have written a fair few programs before. Writing for the kernel, however, is quite different from writing userland applications. It would be unnecssary to cover them all in a single post (especially the introduction), but it usually boils down to the fact that you no longer have the glibc at your disposal, you have a restricted set of string functions to choose from (albeit I have no gripes as it's fairly robust), and now most of your core function names have a 'k' somewhere in it (kmalloc, printk, etc.).

### Generic LKM

The following is a template for a generic kernel module and its corresponding makefile. It has no functionality other than to output `Hello, world!`, but you can practice loading and unloading the kernel module with `lsmod` and `rmmod` respectively.

```c
/* hello.c */
#include <linux/module.h> /* Needed by all modules */
#include <linux/kernel.h>

int init_module(void){
	printk(KERN_INFO "Hello, world!");
	return 0;
}

void cleanup_module(void){
	return;
}
```

We can break this code down into 3 distinct parts:

Header Files
* The header files we include are `module.h` and `kernel.h`. `module.h` is needed by all kernel modules. `kernel.h` is needed to use the kernel macro expansion (KERN_INFO) in `printk()`.

`init_module()`
* The `init_module()` function is called when you first load the kernel module into the kernel with `lsmod`. Because of this, it is only ever called once which makes it a good place to spawn all of your kernel threads or hook functions.

`cleanup_module()`
* Conversely, the `cleanup_module()` function is called when you unload the kernel module from the kernel with `rmmod`. This function is only ever called once which makes it a good place to perform all of the necessary tasks that return the kernel to the state it was in before you loaded the module.

```makefile
#Makefile
MODULE := hello

obj-m := $(MODULE).o

default: all

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```

This is a generic makefile that is used to compile kernel modules. This makefile assumes the initial source filename is `hello.c`. The name of the resulting file will be `hello.ko`. To insert the kernel module into your kernel, run the command `sudo insmod hello.ko`. To remove the kernel module from your kernel, run the command `sudo rmmod hello`.

To see the output of the kernel module, I recommend opening another terminal and running the command `watch journalctl -r -k -a`. To quickly break that down, `watch` refreshes the output every 2 seconds by default, `journalctl` shows your system logs, `-r` prints the log in reverse (latest messages are at the top), `-k` prints kernel messages only, and `-a` makes `journalctl` print all characters even unprintable characters or characters that go past the normal limit.

For an extended (but outdated) reference to an introduction to kernel module development, please visit the [TLDP Kernel Module Programming Guide](<http://www.tldp.org/LDP/lkmpg/2.6/html>).

### LKM Development Issues

If you are looking to develop a LKM for your kernel in order to add some additional functionality (I'm assuming you are), I have unfortunate news. The documentation for kernel module development is extremely scarce. Also, including the TLDP guide I linked earlier, most of the currently available documentation online has outdated instructions. They are typically targeting the Linux kernel versions from 2.4 (2001) to 2.6 (2003). I have found that looking at recently created kernel modules and LKM rootkits on Github as well as the kernel source code of the kernel version you're targeting is the most effective way to develop a LKM.

