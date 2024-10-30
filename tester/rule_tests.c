#include "rule_tests.h"

void print_rule(fire_Rule *rule)
{

    if (rule == NULL)
    {
        return;
    }
    printf("Parsed rule ID: %d\n", rule->id);
    printf("Source address: %d.%d.%d.%d-%d.%d.%d.%d\n",
           (unsigned char)rule->source_addresses[0], (unsigned char)rule->source_addresses[1], (unsigned char)rule->source_addresses[2], (unsigned char)rule->source_addresses[3],
           (unsigned char)rule->source_addresses[4], (unsigned char)rule->source_addresses[5], (unsigned char)rule->source_addresses[6], (unsigned char)rule->source_addresses[7]);
    printf("Source port: %d\n", rule->source_port);
    printf("Dest address: %d.%d.%d.%d-%d.%d.%d.%d\n",
           (unsigned char)rule->destination_addresses[0], (unsigned char)rule->destination_addresses[1], (unsigned char)rule->destination_addresses[2], (unsigned char)rule->destination_addresses[3],
           (unsigned char)rule->destination_addresses[4], (unsigned char)rule->destination_addresses[5], (unsigned char)rule->destination_addresses[6], (unsigned char)rule->destination_addresses[7]);
    printf("Dest port: %d\n", rule->destination_port);
    printf("Protocol: %s\n", rule->proto == fire_proto_TCP ? "TCP" : "UDP");
    printf("Action: %s\n", rule->action == fire_ACCEPT ? "ACCEPT" : "DROP");
    printf("Direction: %s\n", rule->direction == fire_dir_INBOUND ? "INBOUND" : "OUTBOUND");
    printf("Enabled: %s\n", rule->enabled == fire_TRUE ? "true" : "false");
}

int test_rule_count1()
{
    return GetRuleCount("{}{}{}", 6);
    return 1;
}

int test_rule_count2()
{
    return GetRuleCount("{}{}{}{}{}", 10);
    return 1;
}

int test_rules_parse1()
{
    const char *json_string = "{"
                              "\"id\": 67,"
                              "\"source_address\": \"0.99.0.0-255.255.255.254\","
                              "\"source_port\": \"65535\","
                              "\"destination_address\": \"0.0.0.0-255.255.255.255\","
                              "\"destination_port\": \"999999\","
                              "\"protocol\": \"TCP\","
                              "\"action\": \"ACCEPT\","
                              "\"direction\": \"INBOUND\","
                              "\"enabled\": true,"
                              "\"description\": \"\""
                              "}";

    fire_Rule rule = parse_json_to_rule((char *)json_string);
    if (rule.id != -1)
    {
        printf("Parsed rule ID: %d\n", rule.id);
        printf("Source address: %d.%d.%d.%d-%d.%d.%d.%d\n",
               (unsigned char)rule.source_addresses[0], (unsigned char)rule.source_addresses[1], (unsigned char)rule.source_addresses[2], (unsigned char)rule.source_addresses[3],
               (unsigned char)rule.source_addresses[4], (unsigned char)rule.source_addresses[5], (unsigned char)rule.source_addresses[6], (unsigned char)rule.source_addresses[7]);
        printf("Source port: %d\n", rule.source_port);
        printf("Dest address: %d.%d.%d.%d-%d.%d.%d.%d\n",
               (unsigned char)rule.destination_addresses[0], (unsigned char)rule.destination_addresses[1], (unsigned char)rule.destination_addresses[2], (unsigned char)rule.destination_addresses[3],
               (unsigned char)rule.destination_addresses[4], (unsigned char)rule.destination_addresses[5], (unsigned char)rule.destination_addresses[6], (unsigned char)rule.destination_addresses[7]);
        printf("Dest port: %d\n", rule.destination_port);
        printf("Protocol: %s\n", rule.proto == fire_proto_TCP ? "TCP" : "UDP");
        printf("Action: %s\n", rule.action == fire_ACCEPT ? "ACCEPT" : "DROP");
        printf("Direction: %s\n", rule.direction == fire_dir_INBOUND ? "INBOUND" : "OUTBOUND");
        printf("Enabled: %s\n", rule.enabled == fire_TRUE ? "true" : "false");
    }
    else
    {
        printf("error parsing rule\n");
    }
    return 1;
}

int test_rules_parse2()
{
    const char *json_string = "["
                              "{"
                              "\"id\": 0,"
                              "\"source_address\": \"0.99.0.0-255.255.255.254\","
                              "\"source_port\": \"65535\","
                              "\"destination_address\": \"0.0.0.0-255.255.255.255\","
                              "\"destination_port\": \"999999\","
                              "\"protocol\": \"TCP\","
                              "\"action\": \"ACCEPT\","
                              "\"direction\": \"INBOUND\","
                              "\"enabled\": true,"
                              "\"description\": \"\""
                              "},"
                              "{"
                              "\"id\": 1,"
                              "\"source_address\": \"0.99.0.0-255.255.255.253\","
                              "\"source_port\": \"65535\","
                              "\"destination_address\": \"0.0.0.0-255.255.255.255\","
                              "\"destination_port\": \"999999\","
                              "\"protocol\": \"TCP\","
                              "\"action\": \"ACCEPT\","
                              "\"direction\": \"INBOUND\","
                              "\"enabled\": true,"
                              "\"description\": \"\""
                              "},"
                              "{"
                              "\"id\": 2,"
                              "\"source_address\": \"0.99.0.0-255.255.255.252\","
                              "\"source_port\": \"65535\","
                              "\"destination_address\": \"0.0.0.0-255.255.255.255\","
                              "\"destination_port\": \"999999\","
                              "\"protocol\": \"TCP\","
                              "\"action\": \"ACCEPT\","
                              "\"direction\": \"OUTBOUND\","
                              "\"enabled\": true,"
                              "\"description\": \"\""
                              "}"
                              "]";
    int count = GetRuleCount((char *)json_string, strlen(json_string));
    printf("count is %d\n", count);
    if (count != 3)
    {
        printf("count is %d and not 3\n", count);
        return -1;
    }

    // parse_json_list();

    return count;
}

int test_rules_parse3()
{
    const char *json_string = "["
                              "{"
                              "\"id\": 0,"
                              "\"source_address\": \"0.99.0.0-255.255.255.254\","
                              "\"source_port\": \"65535\","
                              "\"destination_address\": \"0.0.0.0-255.255.255.255\","
                              "\"destination_port\": \"999999\","
                              "\"protocol\": \"TCP\","
                              "\"action\": \"ACCEPT\","
                              "\"direction\": \"INBOUND\","
                              "\"enabled\": true,"
                              "\"description\": \"\""
                              "},"
                              "{"
                              "\"id\": 1,"
                              "\"source_address\": \"0.99.0.0-255.255.255.253\","
                              "\"source_port\": \"65535\","
                              "\"destination_address\": \"0.0.0.0-255.255.255.255\","
                              "\"destination_port\": \"999999\","
                              "\"protocol\": \"TCP\","
                              "\"action\": \"ACCEPT\","
                              "\"direction\": \"INBOUND\","
                              "\"enabled\": true,"
                              "\"description\": \"\""
                              "},"
                              "{"
                              "\"id\": 2,"
                              "\"source_address\": \"0.99.0.0-255.255.255.252\","
                              "\"source_port\": \"65535\","
                              "\"destination_address\": \"0.0.0.0-255.255.255.255\","
                              "\"destination_port\": \"999999\","
                              "\"protocol\": \"TCP\","
                              "\"action\": \"ACCEPT\","
                              "\"direction\": \"OUTBOUND\","
                              "\"enabled\": true,"
                              "\"description\": \"\""
                              "},"
                              "]";
    int count = GetRuleCount((char *)json_string, strlen(json_string));
    printf("count is %d\n", count);
    if (count != 3)
    {
        printf("count is %d and not 3\n", count);
        return -1;
    }

    fire_Rule *ptr = parse_json_list((char *)json_string, count);
    if (ptr == NULL)
    {
        printf("got NULL ptr from parse_json_list\n");
        return -1;
    }
    else
    {
        free(ptr);
        return 1;
    }
}

int test_rules_parse4()
{
    const char *json_string = "["
                              "{"
                              "\"id\": 0,"
                              "\"source_address\": \"0.99.0.0-255.255.255.254\","
                              "\"source_port\": \"65535\","
                              "\"destination_address\": \"0.0.0.0-255.255.255.255\","
                              "\"destination_port\": \"999999\","
                              "\"protocol\": \"TCP\","
                              "\"action\": \"ACCEPT\","
                              "\"direction\": \"OUTBOUND\","
                              "\"enabled\": true,"
                              "\"description\": \"\""
                              "},"
                              "{"
                              "\"id\": 1,"
                              "\"source_address\": \"0.99.0.0-255.255.255.253\","
                              "\"source_port\": \"65535\","
                              "\"destination_address\": \"0.0.0.0-255.255.255.255\","
                              "\"destination_port\": \"999999\","
                              "\"protocol\": \"TCP\","
                              "\"action\": \"ACCEPT\","
                              "\"direction\": \"INBOUND\","
                              "\"enabled\": true,"
                              "\"description\": \"\""
                              "},"
                              "{"
                              "\"id\": 2,"
                              "\"source_address\": \"0.99.0.0-255.255.255.252\","
                              "\"source_port\": \"65535\","
                              "\"destination_address\": \"0.0.0.0-255.255.255.255\","
                              "\"destination_port\": \"999999\","
                              "\"protocol\": \"TCP\","
                              "\"action\": \"ACCEPT\","
                              "\"direction\": \"INBOUND\","
                              "\"enabled\": true,"
                              "\"description\": \"\""
                              "},"
                              "{"
                              "\"id\": 3,"
                              "\"source_address\": \"0.99.0.0-255.255.255.254\","
                              "\"source_port\": \"65535\","
                              "\"destination_address\": \"0.0.0.0-255.255.255.255\","
                              "\"destination_port\": \"999999\","
                              "\"protocol\": \"TCP\","
                              "\"action\": \"ACCEPT\","
                              "\"direction\": \"OUTBOUND\","
                              "\"enabled\": true,"
                              "\"description\": \"\""
                              "},"
                              "{"
                              "\"id\": 4,"
                              "\"source_address\": \"0.99.0.0-255.255.255.253\","
                              "\"source_port\": \"65535\","
                              "\"destination_address\": \"0.0.0.0-255.255.255.255\","
                              "\"destination_port\": \"999999\","
                              "\"protocol\": \"TCP\","
                              "\"action\": \"ACCEPT\","
                              "\"direction\": \"INBOUND\","
                              "\"enabled\": true,"
                              "\"description\": \"\""
                              "},"
                              "{"
                              "\"id\": 5,"
                              "\"source_address\": \"0.99.0.0-255.255.255.252\","
                              "\"source_port\": \"65535\","
                              "\"destination_address\": \"0.0.0.0-255.255.255.255\","
                              "\"destination_port\": \"999999\","
                              "\"protocol\": \"TCP\","
                              "\"action\": \"ACCEPT\","
                              "\"direction\": \"OUTBOUND\","
                              "\"enabled\": true,"
                              "\"description\": \"\""
                              "}"
                              "]";
    fire_Rule *table_in = NULL;
    int in_amount = 0;
    fire_Rule *table_out = NULL;
    int out_amount = 0;

    fire_BOOL res = ParseRules((char *)json_string, strlen(json_string), &table_in, &in_amount, &table_out, &out_amount);
    // for (int i = 0; i < in_amount; i++)
    //{
    //     print_rule(&(table_in[i]));
    // }
    // for (int i = 0; i < out_amount; i++)
    //{
    //     print_rule(&(table_out[i]));
    // }
    if (res == fire_FALSE)
        return -1;
    else
        return 1;
}
