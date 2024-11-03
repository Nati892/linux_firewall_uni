
#ifndef NET_CONTROL_H
#define NET_CONTROL_H
#include "../Head/stdafx.h"
#define NETLINK_TESTFAMILY 25

// Protocol message types

#define NETLINK_TEST_FAMILY 25
#define MSG_SEND_FILE 1
#define MSG_GET_FILE 2
#define MSG_FILE_DATA 3

// Structure to hold file transfer state
struct file_transfer_state
{
    size_t expected_size;
    size_t received_size;
    unsigned char *data;
    bool size_received;
    bool transfer_in_progress;
};

static struct file_transfer_state transfer_state = {
    .expected_size = 0,
    .received_size = 0,
    .data = NULL,
    .size_received = false,
    .transfer_in_progress = false};

static struct sock *nl_sk = NULL;
static unsigned char *stored_file = NULL;
static size_t stored_size = 0;

static void nl_recv_msg(struct sk_buff *skb);
int netlink_init(void);
void close_netlink(void);

#endif