#ifndef STDAFX_H
#define STDAFX_H

// Imports
#ifdef __KERNEL__
// Code that is compiled in the kernel space
#include <linux/module.h> /* Needed by all modules */
#include <linux/init.h> /* Needed for the macros */
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/net.h>
#include <linux/ip.h>
#include <linux/string.h> // For memcpy
#include <linux/inet.h>   // For inet_ntop
#include <net/sock.h>
#include <linux/types.h> // For kernel types
#include <linux/slab.h>  // For kmalloc and kfree

#else
// Code that is compiled in user space
#include <stdint.h>      // For standard types in user space
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>

#endif


#ifdef __KERNEL__
#define SHARED_UINT32 uint32_t
#define ENDLINE
#else
#define ENDLINE \n
#define SHARED_UINT32 __uint32_t
#endif
// Shared functions
void shared_free(void *ptr);
void* shared_malloc(size_t size) ;

void shared_print(const char *fmt, ...) ;

#endif // STDAFX_H
