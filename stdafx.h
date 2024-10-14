#ifndef STDAFX_H
#define STDAFX_H
#include <linux/init.h> /* Needed for the macros */
#include <linux/kernel.h>
#include <linux/module.h> /* Needed by all modules */
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/net.h>
#include <linux/ip.h>
#include <linux/string.h> // For memcpy
#include <linux/inet.h>   // For inet_ntop
#include <net/sock.h>

#endif