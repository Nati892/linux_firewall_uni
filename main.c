#include <linux/module.h> /* Needed by all modules */
#include <linux/kernel.h>
MODULE_LICENSE("GPL");
#include "Head/stdafx.h"
#include "Rule/t.h"
#include "Rule/Rule.h"

typedef struct
{
    /* User fills in from here down. */
    nf_hookfn *hook;        // callback function
    struct net_device *dev; // network device interface
    void *priv;
    u_int8_t pf;          // protocol
    unsigned int hooknum; // Netfilter hook enum
    /* Hooks are ordered in ascending priority. */
    int priority; // priority of callback function
} nf_hook_ops;

// ip filter
unsigned int nf_in_callback(void *priv,
                            struct sk_buff *skb,
                            const struct nf_hook_state *state);

// full blocker
unsigned int nf_in_callback_dropper(void *priv,
                                    struct sk_buff *skb,
                                    const struct nf_hook_state *state);

// full informer local_in
unsigned int nf_in_callback_informer(void *priv,
                                     struct sk_buff *skb,
                                     const struct nf_hook_state *state);

// full informer local_in
unsigned int nf_pre_routing_callback_informer(void *priv,
                                              struct sk_buff *skb,
                                              const struct nf_hook_state *state);

unsigned int nf_out_hook(void *priv,
                         struct sk_buff *skb,
                         const struct nf_hook_state *state);

static struct nf_hook_ops *nf_init_block_ops = NULL;
static struct nf_hook_ops *nf_pre_route_block_ops = NULL;

static void RunTests(void)
{
    shared_print(KERN_INFO "firemod: starting tests in kernel!");
   // Testy1();
    shared_print(KERN_INFO "firemod: end of tests in kernel!");
}

static int __init hello_init(void)
{
    // allocate mem for ops structs
    nf_init_block_ops = (struct nf_hook_ops *)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
    nf_pre_route_block_ops = (struct nf_hook_ops *)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);

    // config and register hooks
    if (nf_init_block_ops != NULL)
    {
        nf_init_block_ops->hook = (nf_hookfn *)nf_in_callback_informer;
        nf_init_block_ops->hooknum = NF_INET_LOCAL_IN;
        nf_init_block_ops->pf = NFPROTO_IPV4;
        nf_init_block_ops->priority = NF_IP_PRI_LAST; // set the priority

        nf_register_net_hook(&init_net, nf_init_block_ops);
    }

    // config and register hooks
    if (nf_pre_route_block_ops != NULL)
    {
        nf_pre_route_block_ops->hook = (nf_hookfn *)nf_pre_routing_callback_informer;
        nf_pre_route_block_ops->hooknum = NF_INET_PRE_ROUTING;
        nf_pre_route_block_ops->pf = NFPROTO_IPV4;
        nf_pre_route_block_ops->priority = NF_IP_PRI_LAST; // set the priority

        nf_register_net_hook(&init_net, nf_pre_route_block_ops);
    }
    shared_print(KERN_INFO "firemod: Hello, world1\n");

    shared_print(KERN_INFO "firemod: calling tests in kernel!\n");
    RunTests();

    return 0;
}

static void __exit hello_exit(void)
{
    if (nf_init_block_ops != NULL)
    {
        nf_unregister_net_hook(&init_net, nf_init_block_ops);
        shared_free(nf_init_block_ops);
    }

    if (nf_pre_route_block_ops != NULL)
    {
        nf_unregister_net_hook(&init_net, nf_pre_route_block_ops);
        shared_free(nf_pre_route_block_ops);
    }

    shared_print(KERN_INFO "firemod:Goodbye, world\n");
}

#define ALLOWED_IP "192.168.1.61"

unsigned int nf_in_callback(void *priv,
                            struct sk_buff *skb,
                            const struct nf_hook_state *state)
{
    char src_ip[16];     // Buffer for source IP
    char dst_ip[16];     // Buffer for destination IP
    struct iphdr *iph;   // IP header
    struct udphdr *udph; // UDP header
    struct tcphdr *tcph;
    u32 specific_ip;

    if (!skb)
        return NF_ACCEPT;
    iph = ip_hdr(skb);
    snprintf(src_ip, sizeof(src_ip), "%pI4", &iph->saddr);
    snprintf(dst_ip, sizeof(dst_ip), "%pI4", &iph->daddr);
    // retrieve the IP headers from the packet
    // if(iph->protocol == IPPROTO_UDP) {
    //	udph = udp_hdr(skb);
    //	if(ntohs(udph->dest) == 53) {
    //		return NF_ACCEPT; // accept UDP packet
    //	}
    //}
    specific_ip = in_aton(ALLOWED_IP);

    if (iph->protocol == IPPROTO_TCP)
    {
        tcph = tcp_hdr(skb);

        if (iph->saddr != specific_ip)
        {
            shared_print(KERN_INFO "firemod: ip_dropped packet. src %s:%d, dst %s:%d\n", src_ip, tcph->source, dst_ip, tcph->dest);
            return NF_DROP; // drop TCP packet
        }
        else
        {
            shared_print(KERN_INFO "firemod: ip_accept packet. src %s:%d, dst %s:%d\n", src_ip, tcph->source, dst_ip, tcph->dest);
        }
        if (tcph->dest == 1234)
        {
            shared_print(KERN_INFO "firemod: port_dropped packet. src %s:%d, dst %s:%d\n", src_ip, tcph->source, dst_ip, tcph->dest);
            return NF_DROP; // drop TCP packet
        }
        shared_print(KERN_INFO "firemod: accepted packet. src %s:%d, dst %s:%d\n", src_ip, tcph->source, dst_ip, tcph->dest);
        return NF_ACCEPT; // drop TCP packet
    }
    return NF_DROP;
}

unsigned int nf_in_callback_dropper(void *priv,
                                    struct sk_buff *skb,
                                    const struct nf_hook_state *state)
{
    char src_ip[16];     // Buffer for source IP
    char dst_ip[16];     // Buffer for destination IP
    struct iphdr *iph;   // IP header
    struct udphdr *udph; // UDP header
    struct tcphdr *tcph;
    u32 specific_ip;

    if (!skb)
        return NF_ACCEPT;
    else
        return NF_DROP;
    iph = ip_hdr(skb);
    snprintf(src_ip, sizeof(src_ip), "%pI4", &iph->saddr);
    snprintf(dst_ip, sizeof(dst_ip), "%pI4", &iph->daddr);
    // retrieve the IP headers from the packet
    // if(iph->protocol == IPPROTO_UDP) {
    //	udph = udp_hdr(skb);
    //	if(ntohs(udph->dest) == 53) {
    //		return NF_ACCEPT; // accept UDP packet
    //	}
    //}
    specific_ip = in_aton(ALLOWED_IP);

    if (iph->protocol == IPPROTO_TCP)
    {
        tcph = tcp_hdr(skb);

        if (iph->saddr != specific_ip)
        {
            shared_print(KERN_INFO "firemod: ip_dropped packet. src %s:%d, dst %s:%d\n", src_ip, tcph->source, dst_ip, tcph->dest);
            return NF_DROP; // drop TCP packet
        }
        else
        {
            shared_print(KERN_INFO "firemod: ip_accept packet. src %s:%d, dst %s:%d\n", src_ip, tcph->source, dst_ip, tcph->dest);
        }
        if (tcph->dest == 1234)
        {
            shared_print(KERN_INFO "firemod: port_dropped packet. src %s:%d, dst %s:%d\n", src_ip, tcph->source, dst_ip, tcph->dest);
            return NF_DROP; // drop TCP packet
        }
        shared_print(KERN_INFO "firemod: accepted packet. src %s:%d, dst %s:%d\n", src_ip, tcph->source, dst_ip, tcph->dest);
        return NF_ACCEPT; // drop TCP packet
    }
    return NF_DROP;
}

unsigned int nf_in_callback_informer(void *priv,
                                     struct sk_buff *skb,
                                     const struct nf_hook_state *state)
{
    char src_ip[16];   // Buffer for source IP
    char dst_ip[16];   // Buffer for destination IP
    struct iphdr *iph; // IP header
    struct tcphdr *tcph;
    struct sock *sk;
    pid_t pid = 0;

    if (!skb)
        return NF_ACCEPT;
    iph = ip_hdr(skb);

    snprintf(src_ip, sizeof(src_ip), "%pI4", &iph->saddr);
    snprintf(dst_ip, sizeof(dst_ip), "%pI4", &iph->daddr);
    if (iph->protocol == IPPROTO_TCP)
    {
        tcph = tcp_hdr(skb);

        sk = skb->sk;
        if (sk && sk->sk_socket && sk->sk_socket->file)
        {
            pid = pid_vnr(sk->sk_socket->file->f_owner.pid);
        }
        shared_print(KERN_INFO "firemod: inform src %s:%d, dst %s:%d LOCAL_IN, pid: %d\n", src_ip, ntohs(tcph->source), dst_ip, ntohs(tcph->dest), pid);
    }
    return NF_ACCEPT;
}

unsigned int nf_pre_routing_callback_informer(void *priv,
                                              struct sk_buff *skb,
                                              const struct nf_hook_state *state)
{
    char src_ip[16];   // Buffer for source IP
    char dst_ip[16];   // Buffer for destination IP
    struct iphdr *iph; // IP header
    struct tcphdr *tcph;

    if (!skb)
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    snprintf(src_ip, sizeof(src_ip), "%pI4", &iph->saddr);
    snprintf(dst_ip, sizeof(dst_ip), "%pI4", &iph->daddr);
    if (iph->protocol == IPPROTO_TCP)
    {
        tcph = tcp_hdr(skb);

        shared_print(KERN_INFO "firemod: inform src %s:%d, dst %s:%d PRE_ROUTING\n", src_ip, ntohs(tcph->source), dst_ip, ntohs(tcph->dest));
    }
    return NF_ACCEPT;
}
module_init(hello_init);
module_exit(hello_exit);
