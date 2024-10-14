#ifndef RULE_H
#define RULE_H

#ifdef __KERNEL__
#include <linux/types.h>  // For kernel types
#else
#include <stdint.h>       // For standard types in user space
#endif


// Boolean type definition
typedef enum fire_BOOL
{
    proto_TRUE,
    proto_FALSE
} fire_BOOL;

// Network protocol enum definition
typedef enum fire_net_protocol
{
    proto_TCP,
    proto_UDP
} fire_net_protocol;

// Action enum definition
typedef enum fire_action
{
    proto_ACCEPT,
    proto_DROP
} fire_action;

// Direction enum definition
typedef enum fire_direction
{
    proto_INBOUND,
    proto_OUTBOUND
} fire_direction;

// Rule struct definition
typedef struct fire_Rule
{
    uint32_t id;
    char source_addresses[8];
    uint32_t source_port;
    char destination_addresses[8];
    uint32_t destination_port;
    fire_net_protocol proto;
    fire_action action;
    fire_direction direction;
    fire_BOOL enabled;
} fire_Rule;

#endif // RULE_H