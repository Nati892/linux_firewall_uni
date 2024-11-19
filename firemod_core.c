#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/timer.h>
#include "Head/stdafx.h"
#include "Rule/Rule.h"
#include "Rule/RuleParser.h"
#include "tester/rule_tests.h"
#include "tester/main.h"
#include "Control/net_control.h"
#include "Control/mod_config.h"

typedef struct
{
    nf_hookfn *hook;
    struct net_device *dev;
    void *priv;
    u_int8_t pf;
    unsigned int hooknum;
    int priority;
} nf_hook_ops;

// Timer declarations
static struct timer_list config_timer;
static int counter = 0;
static bool first_run = true;

// Timer callback function
static void timer_callback(struct timer_list *t)
{
    // Reschedule the timer
    mod_timer(&config_timer, jiffies + msecs_to_jiffies(1000));
}

//// ip filter
// unsigned int nf_in_callback(void *priv,
//                             struct sk_buff *skb,
//                             const struct nf_hook_state *state);
//
//// full blocker
// unsigned int nf_in_callback_dropper(void *priv,
//                                     struct sk_buff *skb,
//                                     const struct nf_hook_state *state);
//
//// full informer local_in
// unsigned int nf_in_callback_informer(void *priv,
//                                      struct sk_buff *skb,
//                                      const struct nf_hook_state *state);
//
//// full informer local_in
// unsigned int nf_pre_routing_callback_informer(void *priv,
//                                               struct sk_buff *skb,
//                                               const struct nf_hook_state *state);
//
// unsigned int nf_out_hook(void *priv,
//                          struct sk_buff *skb,
//                          const struct nf_hook_state *state);

static struct nf_hook_ops *nf_inbound_block_ops = NULL;
static struct nf_hook_ops *nf_outbound_block_ops = NULL;

unsigned int process_inbound_traffic(void *priv,
                                     struct sk_buff *skb,
                                     const struct nf_hook_state *state);

unsigned int process_outbound_traffic(void *priv,
                                      struct sk_buff *skb,
                                      const struct nf_hook_state *state);

int __init fire_module_init(void)
{
    nf_inbound_block_ops = (struct nf_hook_ops *)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
    nf_outbound_block_ops = (struct nf_hook_ops *)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);

    if (nf_inbound_block_ops != NULL)
    {
        nf_inbound_block_ops->hook = (nf_hookfn *)process_inbound_traffic;
        nf_inbound_block_ops->hooknum = NF_INET_LOCAL_IN;
        nf_inbound_block_ops->pf = NFPROTO_IPV4;
        nf_inbound_block_ops->priority = NF_IP_PRI_LAST;
        nf_register_net_hook(&init_net, nf_inbound_block_ops);
    }

    if (nf_outbound_block_ops != NULL)
    {
        nf_outbound_block_ops->hook = (nf_hookfn *)process_outbound_traffic;
        nf_outbound_block_ops->hooknum = NF_INET_LOCAL_OUT;
        nf_outbound_block_ops->pf = NFPROTO_IPV4;
        nf_outbound_block_ops->priority = NF_IP_PRI_LAST;
        nf_register_net_hook(&init_net, nf_outbound_block_ops);
    }

    // Initialize timer
    timer_setup(&config_timer, timer_callback, 0);
    mod_timer(&config_timer, jiffies + msecs_to_jiffies(1000));

    shared_print("firemod kernel module firewall loading\n");
    init_config_file();

    int netlink_res = netlink_init();
    if (netlink_res != 0)
    {
        shared_print("firemod: BAD INIT FOR NETLINK\n");
    }
    else
    {
        shared_print("firemod: GOOD INIT FOR NETLINK\n");
    }

    return 0;
}

void __exit fire_module_exit(void)
{
    shared_print("firemod:unloading function started\n");

    if (nf_inbound_block_ops != NULL)
    {
        nf_unregister_net_hook(&init_net, nf_inbound_block_ops);
        shared_free(nf_inbound_block_ops);
    }

    if (nf_outbound_block_ops != NULL)
    {
        nf_unregister_net_hook(&init_net, nf_outbound_block_ops);
        shared_free(nf_outbound_block_ops);
    }

    // Delete timer
    del_timer_sync(&config_timer);

    close_netlink();
    cleanup_config();
    shared_print("firemod:unloading function ended\n");
}

unsigned int process_inbound_traffic(void *priv,
                                     struct sk_buff *skb,
                                     const struct nf_hook_state *state)
{
    char src_ip[16], dst_ip[16];
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct udphdr *udph;
    int i;
    const char *proto_str;

    if (!skb)
        return NF_ACCEPT;
    
    iph = ip_hdr(skb);
    if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
        return NF_ACCEPT;

    snprintf(src_ip, sizeof(src_ip), "%pI4", &iph->saddr);
    snprintf(dst_ip, sizeof(dst_ip), "%pI4", &iph->daddr);

    mutex_lock(&current_running_mutex);
    for (i = 0; i < running_table_in_amount; i++)
    {
        if (!running_table_in[i].enabled)
            continue;

        // Check protocol match
        if (running_table_in[i].proto != fire_proto_ANY) {
            if ((iph->protocol == IPPROTO_TCP && running_table_in[i].proto != fire_proto_TCP) ||
                (iph->protocol == IPPROTO_UDP && running_table_in[i].proto != fire_proto_UDP))
                continue;
        }

        // Get ports based on protocol
        __be16 src_port, dst_port;
        if (iph->protocol == IPPROTO_TCP) {
            tcph = tcp_hdr(skb);
            src_port = tcph->source;
            dst_port = tcph->dest;
            proto_str = "TCP";
        } else {
            udph = udp_hdr(skb);
            src_port = udph->source;
            dst_port = udph->dest;
            proto_str = "UDP";
        }

        if (running_table_in[i].source_address == iph->saddr &&
            running_table_in[i].destination_address == iph->daddr &&
            running_table_in[i].source_port == src_port &&
            running_table_in[i].destination_port == dst_port)
        {
            int action = (running_table_in[i].action == fire_ACCEPT) ? NF_ACCEPT : NF_DROP;
            mutex_unlock(&current_running_mutex);
            shared_print("firemod_report: Inbound match rule[%d] - proto=%s src %s:%d dst %s:%d action=%s\n",
                         i, proto_str, src_ip, ntohs(src_port), dst_ip, ntohs(dst_port),
                         action == NF_DROP ? "DROP" : "ACCEPT");
            return action;
        }
    }
    mutex_unlock(&current_running_mutex);
    
    proto_str = (iph->protocol == IPPROTO_TCP) ? "TCP" : "UDP";
    __be16 sport = (iph->protocol == IPPROTO_TCP) ? tcp_hdr(skb)->source : udp_hdr(skb)->source;
    __be16 dport = (iph->protocol == IPPROTO_TCP) ? tcp_hdr(skb)->dest : udp_hdr(skb)->dest;
    
    shared_print("firemod_report: Inbound no rule match - proto=%s src %s:%d dst %s:%d action=ACCEPT\n",
                 proto_str, src_ip, ntohs(sport), dst_ip, ntohs(dport));
    return NF_ACCEPT;
}

unsigned int process_outbound_traffic(void *priv,
                                      struct sk_buff *skb,
                                      const struct nf_hook_state *state)
{
    char src_ip[16], dst_ip[16];
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct udphdr *udph;
    int i;
    const char *proto_str;

    if (!skb)
        return NF_ACCEPT;
    
    iph = ip_hdr(skb);
    if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
        return NF_ACCEPT;

    snprintf(src_ip, sizeof(src_ip), "%pI4", &iph->saddr);
    snprintf(dst_ip, sizeof(dst_ip), "%pI4", &iph->daddr);

    mutex_lock(&current_running_mutex);
    for (i = 0; i < running_table_out_amount; i++)
    {
        if (!running_table_out[i].enabled)
            continue;

        // Check protocol match
        if (running_table_out[i].proto != fire_proto_ANY) {
            if ((iph->protocol == IPPROTO_TCP && running_table_out[i].proto != fire_proto_TCP) ||
                (iph->protocol == IPPROTO_UDP && running_table_out[i].proto != fire_proto_UDP))
                continue;
        }

        // Get ports based on protocol
        __be16 src_port, dst_port;
        if (iph->protocol == IPPROTO_TCP) {
            tcph = tcp_hdr(skb);
            src_port = tcph->source;
            dst_port = tcph->dest;
            proto_str = "TCP";
        } else {
            udph = udp_hdr(skb);
            src_port = udph->source;
            dst_port = udph->dest;
            proto_str = "UDP";
        }

        if (running_table_out[i].source_address == iph->saddr &&
            running_table_out[i].destination_address == iph->daddr &&
            running_table_out[i].source_port == src_port &&
            running_table_out[i].destination_port == dst_port)
        {
            int action = (running_table_out[i].action == fire_ACCEPT) ? NF_ACCEPT : NF_DROP;
            mutex_unlock(&current_running_mutex);
            shared_print("firemod_report: Outbound match rule[%d] - proto=%s src %s:%d dst %s:%d action=%s\n",
                         i, proto_str, src_ip, ntohs(src_port), dst_ip, ntohs(dst_port),
                         action == NF_DROP ? "DROP" : "ACCEPT");
            return action;
        }
    }
    mutex_unlock(&current_running_mutex);

    proto_str = (iph->protocol == IPPROTO_TCP) ? "TCP" : "UDP";
    __be16 sport = (iph->protocol == IPPROTO_TCP) ? tcp_hdr(skb)->source : udp_hdr(skb)->source;
    __be16 dport = (iph->protocol == IPPROTO_TCP) ? tcp_hdr(skb)->dest : udp_hdr(skb)->dest;

    shared_print("firemod_report: Outbound no rule match - proto=%s src %s:%d dst %s:%d action=ACCEPT\n",
                 proto_str, src_ip, ntohs(sport), dst_ip, ntohs(dport));
    return NF_ACCEPT;
}

// #define ALLOWED_IP "192.168.1.61"
//
// unsigned int nf_in_callback(void *priv,
//                             struct sk_buff *skb,
//                             const struct nf_hook_state *state)
//{
//     char src_ip[16];     // Buffer for source IP
//     char dst_ip[16];     // Buffer for destination IP
//     struct iphdr *iph;   // IP header
//     struct udphdr *udph; // UDP header
//     struct tcphdr *tcph;
//     u32 specific_ip;
//
//     if (!skb)
//         return NF_ACCEPT;
//     iph = ip_hdr(skb);
//     snprintf(src_ip, sizeof(src_ip), "%pI4", &iph->saddr);
//     snprintf(dst_ip, sizeof(dst_ip), "%pI4", &iph->daddr);
//     specific_ip = in_aton(ALLOWED_IP);
//
//     if (iph->protocol == IPPROTO_TCP)
//     {
//         tcph = tcp_hdr(skb);
//
//         if (iph->saddr != specific_ip)
//         {
//             shared_print(KERN_INFO "firemod: ip_dropped packet. src %s:%d, dst %s:%d\n", src_ip, tcph->source, dst_ip, tcph->dest);
//             return NF_DROP; // drop TCP packet
//         }
//         else
//         {
//             shared_print(KERN_INFO "firemod: ip_accept packet. src %s:%d, dst %s:%d\n", src_ip, tcph->source, dst_ip, tcph->dest);
//         }
//         if (tcph->dest == 1234)
//         {
//             shared_print(KERN_INFO "firemod: port_dropped packet. src %s:%d, dst %s:%d\n", src_ip, tcph->source, dst_ip, tcph->dest);
//             return NF_DROP; // drop TCP packet
//         }
//         shared_print(KERN_INFO "firemod: accepted packet. src %s:%d, dst %s:%d\n", src_ip, tcph->source, dst_ip, tcph->dest);
//         return NF_ACCEPT; // drop TCP packet
//     }
//     return NF_DROP;
// }
//
// unsigned int nf_in_callback_dropper(void *priv,
//                                     struct sk_buff *skb,
//                                     const struct nf_hook_state *state)
//{
//     char src_ip[16];     // Buffer for source IP
//     char dst_ip[16];     // Buffer for destination IP
//     struct iphdr *iph;   // IP header
//     struct udphdr *udph; // UDP header
//     struct tcphdr *tcph;
//     u32 specific_ip;
//
//     if (!skb)
//         return NF_ACCEPT;
//     else
//         return NF_DROP;
//     iph = ip_hdr(skb);
//     snprintf(src_ip, sizeof(src_ip), "%pI4", &iph->saddr);
//     snprintf(dst_ip, sizeof(dst_ip), "%pI4", &iph->daddr);
//     specific_ip = in_aton(ALLOWED_IP);
//
//     if (iph->protocol == IPPROTO_TCP)
//     {
//         tcph = tcp_hdr(skb);
//
//         if (iph->saddr != specific_ip)
//         {
//             shared_print(KERN_INFO "firemod: ip_dropped packet. src %s:%d, dst %s:%d\n", src_ip, tcph->source, dst_ip, tcph->dest);
//             return NF_DROP; // drop TCP packet
//         }
//         else
//         {
//             shared_print(KERN_INFO "firemod: ip_accept packet. src %s:%d, dst %s:%d\n", src_ip, tcph->source, dst_ip, tcph->dest);
//         }
//         if (tcph->dest == 1234)
//         {
//             shared_print(KERN_INFO "firemod: port_dropped packet. src %s:%d, dst %s:%d\n", src_ip, tcph->source, dst_ip, tcph->dest);
//             return NF_DROP; // drop TCP packet
//         }
//         shared_print(KERN_INFO "firemod: accepted packet. src %s:%d, dst %s:%d\n", src_ip, tcph->source, dst_ip, tcph->dest);
//         return NF_ACCEPT; // drop TCP packet
//     }
//     return NF_DROP;
// }
//
// unsigned int nf_in_callback_informer(void *priv,
//                                      struct sk_buff *skb,
//                                      const struct nf_hook_state *state)
//{
//     char src_ip[16];   // Buffer for source IP
//     char dst_ip[16];   // Buffer for destination IP
//     struct iphdr *iph; // IP header
//     struct tcphdr *tcph;
//     struct sock *sk;
//     pid_t pid = 0;
//
//     if (!skb)
//         return NF_ACCEPT;
//     iph = ip_hdr(skb);
//
//     snprintf(src_ip, sizeof(src_ip), "%pI4", &iph->saddr);
//     snprintf(dst_ip, sizeof(dst_ip), "%pI4", &iph->daddr);
//     if (iph->protocol == IPPROTO_TCP)
//     {
//         tcph = tcp_hdr(skb);
//
//         sk = skb->sk;
//         if (sk && sk->sk_socket && sk->sk_socket->file)
//         {
//             pid = pid_vnr(sk->sk_socket->file->f_owner.pid);
//         }
//         shared_print(KERN_INFO "firemod: inform src %s:%d, dst %s:%d LOCAL_IN, pid: %d\n", src_ip, ntohs(tcph->source), dst_ip, ntohs(tcph->dest), pid);
//     }
//     return NF_ACCEPT;
// }
//
// unsigned int nf_pre_routing_callback_informer(void *priv,
//                                               struct sk_buff *skb,
//                                               const struct nf_hook_state *state)
//{
//     char src_ip[16];   // Buffer for source IP
//     char dst_ip[16];   // Buffer for destination IP
//     struct iphdr *iph; // IP header
//     struct tcphdr *tcph;
//
//     if (!skb)
//         return NF_ACCEPT;
//
//     iph = ip_hdr(skb);
//     snprintf(src_ip, sizeof(src_ip), "%pI4", &iph->saddr);
//     snprintf(dst_ip, sizeof(dst_ip), "%pI4", &iph->daddr);
//     if (iph->protocol == IPPROTO_TCP)
//     {
//         tcph = tcp_hdr(skb);
//
//         shared_print(KERN_INFO "firemod: inform src %s:%d, dst %s:%d PRE_ROUTING\n", src_ip, ntohs(tcph->source), dst_ip, ntohs(tcph->dest));
//     }
//     return NF_ACCEPT;
// }
//
module_init(fire_module_init);
module_exit(fire_module_exit);

MODULE_LICENSE("GPL");