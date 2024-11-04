#include "net_control.h"
#include <linux/slab.h>
#include "mod_config.h"

static void set_new_pending_config(file_data *new_data)
{
    unsigned char *new_buffer;
    
    if (new_data == NULL || new_data->size <= 0) {
        shared_print("config: Invalid new config data\n");
        return;
    }

    // Allocate new buffer first
    new_buffer = kmalloc(new_data->size, GFP_KERNEL);
    if (!new_buffer) {
        shared_print("config: Failed to allocate memory for new config\n");
        return;
    }
    
    // Copy data to new buffer
    memcpy(new_buffer, new_data->data, new_data->size);

    mutex_lock(&current_config_pending_change_mutex);
    
    // Free old data if exists
    if (pending_config.data != NULL) {
        kfree(pending_config.data);
        pending_config.data = NULL;
        pending_config.size = 0;
    }

    // Set new data
    pending_config.data = new_buffer;
    pending_config.size = new_data->size;
    
    shared_print("config: Queued new config of size %d\n", new_data->size);
    
    mutex_unlock(&current_config_pending_change_mutex);
}

static void handle_file_data(unsigned char *data, int len)
{
    unsigned char *temp_buffer;
    
    shared_print("handle_file_data started\n");
    
    if (!data || len <= 0) {
        shared_print("handle_file_data: Invalid input\n");
        return;
    }

    // Allocate temporary buffer
    temp_buffer = kmalloc(len, GFP_KERNEL);
    if (!temp_buffer) {
        shared_print("handle_file_data: Failed to allocate memory\n");
        return;
    }

    // Copy data to temporary buffer
    memcpy(temp_buffer, data, len);
    
    // Test parse the data first
    fire_Rule *table_in = NULL;
    int in_amount = 0;
    fire_Rule *table_out = NULL;
    int out_amount = 0;
    
    fire_BOOL res = ParseRules((char *)temp_buffer, len, &table_in, &in_amount, &table_out, &out_amount);
    
    if (res == fire_TRUE) {
        shared_print("netlink: good parsed file\n");
        
        // Create new config data
        file_data new_data;
        new_data.data = temp_buffer;
        new_data.size = len;
        
        // Queue it for processing
        set_new_pending_config(&new_data);
        
        // Clean up parse test data
        kfree(table_in);
        kfree(table_out);
    } else {
        shared_print("netlink: bad parsed file\n");
        kfree(temp_buffer);
    }

    // Clean up stored file if it exists
    if (stored_file) {
        kfree(stored_file);
        stored_file = NULL;
        stored_size = 0;
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
        handle_file_data(data + 1, payload_len);
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
        .flags = NL_CFG_F_NONROOT_RECV};

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