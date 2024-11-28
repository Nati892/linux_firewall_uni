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
    SHARED_UINT32 source_address_start;
    SHARED_UINT32 source_address_end;
    uint32_t source_port_start;
    uint32_t source_port_end;
    SHARED_UINT32 destination_address_start;
    SHARED_UINT32 destination_address_end;
    uint32_t destination_port_start;
    uint32_t destination_port_end;
    fire_net_protocol proto;
    fire_action action;
    fire_direction direction;
    fire_BOOL enabled;
} fire_Rule;

#endif // RULE_H