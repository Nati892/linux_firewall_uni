#ifndef RULE_H
#define RULE_H

// Boolean type definition
typedef enum fire_BOOL
{
    TRUE,
    FALSE
} fire_BOOL;

// Network protocol enum definition
typedef enum fire_net_protocol
{
    proto_tcp,
    proto_udp
} fire_net_protocol;

// Action enum definition
typedef enum fire_action
{
    proto_TCP,
    proto_UDP
} fire_action;

// Direction enum definition
typedef enum fire_direction
{
    INBOUND,
    OUTBOUND
} fire_direction;

// Rule struct definition
typedef struct fire_Rule
{
    int id;
    int source_addresses[8];
    int source_port;
    int destination_addresses[8];
    int destination_port;
    fire_net_protocol proto;
    fire_action action;
    fire_direction direction;
    fire_BOOL enabled;
} fire_Rule;

#endif // RULE_H