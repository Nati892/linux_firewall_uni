#include "net_control.h"
#include <linux/slab.h>
#include "mod_config.h"



static void handle_file_data(unsigned char *data, size_t len)
{
    shared_print("handle_file_data started\n");
    // Free old data if exists
    if (stored_file)
    {
        shared_free(stored_file);
    }

    // Store new data
    stored_file = shared_malloc(len);
    shared_print("handle_file_data rec:%zu\n", len);
    if (stored_file)
    {
        stored_size = len;
        memcpy(stored_file, data, len);
        shared_print("netlink: Stored %zu bytes\n", len);
    }

    fire_Rule *table_in = NULL;
    int in_amount = 0;
    fire_Rule *table_out = NULL;
    int out_amount = 0;

    fire_BOOL res = ParseRules((char *)stored_file, len, &table_in, &in_amount, &table_out, &out_amount);
    if (res == fire_TRUE)
    {
        shared_print("netlink: good parsed file\n");
        file_data new_data;
        new_data.data=data;
        new_data.size=stored_size;
        save_new_config(&new_data);
        shared_free(table_in);
        shared_free(table_out);
    }
    else
    {
        shared_print("netlink: bad parsed file\n");
    }
}

static void send_mock_file(u32 pid)
{
    struct sk_buff *skb;
    struct nlmsghdr *nlh;
    unsigned char mock_data[] = "This is mock file data";
    size_t len = sizeof(mock_data);

    // Allocate socket buffer
    skb = nlmsg_new(len + 4, GFP_KERNEL); // +4 for message type
    if (!skb)
    {
        return;
    }

    // Create message header
    nlh = nlmsg_put(skb, 0, 0, 0, len + 4, 0);
    if (!nlh)
    {
        kfree_skb(skb);
        return;
    }

    // Add message type and data
    *(u32 *)nlmsg_data(nlh) = MSG_FILE_DATA;
    memcpy(nlmsg_data(nlh) + 4, mock_data, len);

    // Send message
    nlmsg_unicast(nl_sk, skb, pid);
    shared_print("netlink: Sent %zu bytes\n", len);
}

static void nl_recv_msg(struct sk_buff *skb)
{
    shared_print("netlink: nl_recv_msg\n");

    struct nlmsghdr *nlh = nlmsg_hdr(skb);
    if (!nlmsg_ok(nlh, skb->len))
    {
        shared_print("netlink: invalid message\n");
        return;
    }

    unsigned char *data = nlmsg_data(nlh);
    u8 msg_type = *data; // Just read first byte
    u32 pid = NETLINK_CB(skb).portid;

    // Calculate actual payload length
    int payload_len = nlmsg_len(nlh) - 1; // subtract message type byte

    shared_print("netlink: nl_recv_msg len:%d\n", payload_len);
    switch (msg_type)
    {
    case MSG_SEND_FILE:
        shared_print("netlink: nl_recv_msg SEND_FILE\n");
        handle_file_data(data + 1, nlh->nlmsg_len - NLMSG_HDRLEN - 1);
        break;

    case MSG_GET_FILE:
        shared_print("netlink: nl_recv_msg GET_FILE\n");
        send_mock_file(pid);
        break;

    default:
        shared_print("netlink: nl_recv_msg %c\n", msg_type);
        break;
    }
}

int netlink_init(void)
{
    struct netlink_kernel_cfg cfg = {
        .input = nl_recv_msg,
    };

    nl_sk = netlink_kernel_create(&init_net, NETLINK_TEST_FAMILY, &cfg);
    if (!nl_sk)
    {
        return -ENOMEM;
    }

    shared_print("netlink loaded\n");
    return 0;
}

void close_netlink(void)
{
    if (stored_file)
    {
        shared_free(stored_file);
    }
    if (nl_sk)
    {
        netlink_kernel_release(nl_sk);
    }
    shared_print("netlink unloaded\n");
}