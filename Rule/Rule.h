#ifndef RULE_H
#define RULE_H
#include "../Head/stdafx.h"


// Boolean type definition
typedef enum fire_BOOL
{
    fire_TRUE,
    fire_FALSE
} fire_BOOL;

// Network protocol enum definition
typedef enum fire_net_protocol
{
    fire_proto_TCP,
    fire_proto_UDP,
    fire_proto_ANY,
} fire_net_protocol;

// Action enum definition
typedef enum fire_action
{
    fire_ACCEPT,
    fire_DROP,
} fire_action;

// Direction enum definition
typedef enum fire_direction
{
    fire_dir_INBOUND,
    fire_dir_OUTBOUND,
} fire_direction;

// Rule struct definition
typedef struct fire_Rule
{
    int32_t id;
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