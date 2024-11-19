#include "net_control.h"
#include <linux/slab.h>
#include "mod_config.h"

// Add to your message types in net_control.h:
#define MSG_SEND_SUCCESS 4
#define MSG_SEND_FAIL 5

static int send_status_response(u32 pid, u32 status)
{
    struct sk_buff *skb;
    struct nlmsghdr *nlh;
    
    // Allocate new socket buffer
    skb = nlmsg_new(4, GFP_KERNEL); // Just sending 4 bytes status
    if (!skb) {
        shared_print("netlink: Failed to allocate response buffer\n");
        return -ENOMEM;
    }

    // Create message header
    nlh = nlmsg_put(skb, 0, 0, 0, 4, 0);
    if (!nlh) {
        shared_print("netlink: Failed to put response header\n");
        kfree_skb(skb);
        return -EMSGSIZE;
    }

    // Set the status
    *(u32 *)nlmsg_data(nlh) = status;

    // Send message
    return nlmsg_unicast(nl_sk, skb, pid);
}

static void set_new_pending_config(file_data *new_data, u32 pid)
{
    unsigned char *new_buffer;
    int ret = MSG_SEND_FAIL;
    
    if (new_data == NULL || new_data->size <= 0) {
        shared_print("config: Invalid new config data\n");
        send_status_response(pid, ret);
        return;
    }

    new_buffer = kmalloc(new_data->size, GFP_KERNEL);
    if (!new_buffer) {
        shared_print("config: Failed to allocate memory for new config\n");
        send_status_response(pid, ret);
        return;
    }
    
    memcpy(new_buffer, new_data->data, new_data->size);

    mutex_lock(&current_config_pending_change_mutex);
    
    if (pending_config.data != NULL) {
        kfree(pending_config.data);
        pending_config.data = NULL;
        pending_config.size = 0;
    }
    
    pending_config.data = new_buffer;
    pending_config.size = new_data->size;
    
    ret = MSG_SEND_SUCCESS;
    
    mutex_unlock(&current_config_pending_change_mutex);
    
    shared_print("config: Queued new config of size %d\n", new_data->size);
    validate_pending_config();
    send_status_response(pid, ret);
}

// Modify handle_file_data to pass the pid
static void handle_file_data(unsigned char *data, int len, u32 pid)
{
    unsigned char *temp_buffer;
    
    shared_print("handle_file_data started\n");
    
    if (!data || len <= 0) {
        shared_print("handle_file_data: Invalid input\n");
        send_status_response(pid, MSG_SEND_FAIL);
        return;
    }

    // Allocate temporary buffer
    temp_buffer = kmalloc(len, GFP_KERNEL);
    if (!temp_buffer) {
        shared_print("handle_file_data: Failed to allocate memory\n");
        send_status_response(pid, MSG_SEND_FAIL);
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
        set_new_pending_config(&new_data, pid);
        
        // Clean up parse test data
        kfree(table_in);
        kfree(table_out);
    } else {
        shared_print("netlink: bad parsed file\n");
        kfree(temp_buffer);
        send_status_response(pid, MSG_SEND_FAIL);
    }

    // Clean up stored file if it exists
    if (stored_file) {
        kfree(stored_file);
        stored_file = NULL;
        stored_size = 0;
    }
}
static void send_config_file(u32 pid)
{
    struct sk_buff *skb;
    struct nlmsghdr *nlh;
    char *config_data;
    size_t len;

    // Get the current config
    config_data = get_config();
    if (!config_data) {
        shared_print("netlink: Failed to get config data\n");
        return;
    }

    len = strlen(config_data);
    shared_print("netlink: Sending config of length %zu\n", len);

    // Allocate socket buffer (+4 for message type)
    skb = nlmsg_new(len + 4, GFP_KERNEL);
    if (!skb) {
        shared_print("netlink: Failed to allocate new socket buffer\n");
        kfree(config_data);
        return;
    }

    // Create message header
    nlh = nlmsg_put(skb, 0, 0, 0, len + 4, 0);
    if (!nlh) {
        shared_print("netlink: Failed to put nlmsg\n");
        kfree_skb(skb);
        kfree(config_data);
        return;
    }

    // Add message type and data
    *(u32 *)nlmsg_data(nlh) = MSG_FILE_DATA;
    memcpy(nlmsg_data(nlh) + 4, config_data, len);

    // Send message
    if (nlmsg_unicast(nl_sk, skb, pid) < 0) {
        shared_print("netlink: Error sending message\n");
    } else {
        shared_print("netlink: Sent config of %zu bytes\n", len);
    }

    // Clean up
    kfree(config_data);
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
        handle_file_data(data + 1, payload_len,pid);
        break;

    case MSG_GET_FILE:
        shared_print("netlink: nl_recv_msg GET_FILE\n");
        send_config_file(pid);
        break;

    default:
        shared_print("netlink: nl_recv_msg %c\n", msg_type);
        break;
    }
    shared_print("finished with netlink callback");
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