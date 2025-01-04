#ifndef STDAFX_H
#define STDAFX_H

// Imports
#ifdef __KERNEL__
// Code that is compiled in the kernel space
#include <linux/module.h>         /* Needed by all modules */
#include <linux/init.h>           /* Needed for the macros */
#include <linux/kernel.h>         // kernel
#include <linux/netfilter.h>      // netfilter
#include <linux/netfilter_ipv4.h> // netfilter
#include <linux/udp.h>            // packet headers
#include <linux/tcp.h>            // packet headers
#include <linux/net.h>            // packet headers
#include <linux/ip.h>             // packet headers
#include <linux/string.h>         // For memcpy
#include <net/sock.h>             // packet headers
#include <linux/types.h>          // For kernel types
#include <linux/slab.h>           // For kmalloc and kfree
#include <linux/netlink.h>        // for netlink socket
#include <linux/fs.h>   
#include <linux/mutex.h>
#include <linux/inet.h>           // For inet_ntop
#include <linux/uaccess.h>
#include <linux/namei.h>
#include <linux/cred.h>
#include <linux/mount.h>
#include <linux/cred.h>
#else
// Code that is compiled in user space
#include <stdint.h> // For standard types in user space
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <linux/netlink.h>        // for netlink socket
#include <arpa/inet.h>      // For ntohl and network functions
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
void *shared_malloc(size_t size);

void shared_print(const char *fmt, ...);

#endif // STDAFX_H
