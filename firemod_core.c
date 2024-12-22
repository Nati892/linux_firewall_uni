#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/timer.h>
#include "Head/stdafx.h"
#include "Rule/Rule.h"
#include "Rule/RuleParser.h"
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
        shared_print("firemod:Error: BAD INIT FOR NETLINK\n");
    }
    else
    {
        shared_print("firemod: GOOD INIT FOR NETLINK\n");
    }

    return 0;
}

void __exit fire_module_exit(void)
{
    shared_print("firemod:unloading module\n");

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
    shared_print("firemod:unloading module ended\n");
}

// HELPER FUNCTIONS
//  Helper function to check if an IP is within a range
static inline bool ip_in_range(SHARED_UINT32 ip, SHARED_UINT32 range_start, SHARED_UINT32 range_end)
{
    return (ntohl(ip) >= ntohl(range_start) && ntohl(ip) <= ntohl(range_end));
}

// Helper function to check if a port is within a range
static inline bool port_in_range(uint16_t port, uint32_t range_start, uint32_t range_end)
{
    return (port >= range_start && port <= range_end);
}
// END OF HELPER FUNCTIONS

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
        if (running_table_in[i].enabled == fire_FALSE)
        {
            shared_print("debug: rule %d not enabled ", i); // debug
            continue;
        }
        shared_print("debug: rule %d is enabled ", i); // debug
        // Check protocol match
        if (running_table_in[i].proto != fire_proto_ANY)
        {
            if ((iph->protocol == IPPROTO_TCP && running_table_in[i].proto != fire_proto_TCP) ||
                (iph->protocol == IPPROTO_UDP && running_table_in[i].proto != fire_proto_UDP))
                continue;
        }

        // Get ports based on protocol
        __be16 src_port, dst_port;
        if (iph->protocol == IPPROTO_TCP)
        {
            tcph = tcp_hdr(skb);
            src_port = tcph->source;
            dst_port = tcph->dest;
            proto_str = "TCP";
        }
        else
        {
            udph = udp_hdr(skb);
            src_port = udph->source;
            dst_port = udph->dest;
            proto_str = "UDP";
        }
        // Convert network byte order ports to host byte order for comparison
        __u16 src_port_host = ntohs(src_port);
        __u16 dst_port_host = ntohs(dst_port);

        if (ip_in_range(iph->saddr, running_table_in[i].source_address_start,
                        running_table_in[i].source_address_end) &&
            ip_in_range(iph->daddr, running_table_in[i].destination_address_start,
                        running_table_in[i].destination_address_end) &&
            port_in_range(src_port_host, running_table_in[i].source_port_start,
                          running_table_in[i].source_port_end) &&
            port_in_range(dst_port_host, running_table_in[i].destination_port_start,
                          running_table_in[i].destination_port_end))
        {
            int action = (running_table_in[i].action == fire_ACCEPT) ? NF_ACCEPT : NF_DROP;
            mutex_unlock(&current_running_mutex);
            if (action == NF_ACCEPT)
            {
                shared_print("firemod_report: Inbound match rule[%d] - proto=%s src %s:%d dst %s:%d action=%s\n",
                             i, proto_str, src_ip, ntohs(src_port_host), dst_ip, ntohs(dst_port_host), "ACCEPT");
            }
            else if (action == NF_DROP)
                shared_print("firemod_report: Inbound match rule[%d] - proto=%s src %s:%d dst %s:%d action=%s\n",
                             i, proto_str, src_ip, ntohs(src_port_host), dst_ip, ntohs(dst_port_host), "DROP");
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
         if (running_table_out[i].enabled==fire_FALSE)
            continue;

        // Check protocol match
        if (running_table_out[i].proto != fire_proto_ANY)
        {
            if ((iph->protocol == IPPROTO_TCP && running_table_out[i].proto != fire_proto_TCP) ||
                (iph->protocol == IPPROTO_UDP && running_table_out[i].proto != fire_proto_UDP))
                continue;
        }

        // Get ports based on protocol
        __be16 src_port, dst_port;
        if (iph->protocol == IPPROTO_TCP)
        {
            tcph = tcp_hdr(skb);
            src_port = tcph->source;
            dst_port = tcph->dest;
            proto_str = "TCP";
        }
        else
        {
            udph = udp_hdr(skb);
            src_port = udph->source;
            dst_port = udph->dest;
            proto_str = "UDP";
        }
        // Convert network byte order ports to host byte order for comparison
        __u16 src_port_host = ntohs(src_port);
        __u16 dst_port_host = ntohs(dst_port);

        if (ip_in_range(iph->saddr, running_table_out[i].source_address_start,
                        running_table_out[i].source_address_end) &&
            ip_in_range(iph->daddr, running_table_out[i].destination_address_start,
                        running_table_out[i].destination_address_end) &&
            port_in_range(src_port_host, running_table_out[i].source_port_start,
                          running_table_out[i].source_port_end) &&
            port_in_range(dst_port_host, running_table_out[i].destination_port_start,
                          running_table_out[i].destination_port_end))
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

module_init(fire_module_init);
module_exit(fire_module_exit);
MODULE_LICENSE("GPL");