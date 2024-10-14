#include "rule_tests.h"

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

int test_rule_parse1()
{
    const char *json_string = "{"
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
                              "}";

    fire_Rule *rule = parse_json_to_rule(json_string);
    if (rule != NULL)
    {
        printf("Parsed rule ID: %d\n", rule->id);
        printf("Source address: %d.%d.%d.%d-%d.%d.%d.%d\n",
               (unsigned char)rule->source_addresses[0], (unsigned char)rule->source_addresses[1], (unsigned char)rule->source_addresses[2], (unsigned char)rule->source_addresses[3],
               (unsigned char)rule->source_addresses[4], (unsigned char)rule->source_addresses[5], (unsigned char)rule->source_addresses[6], (unsigned char)rule->source_addresses[7]);
        printf("Source port: %d\n", rule->source_port);
        printf("Dest address: %d.%d.%d.%d-%d.%d.%d.%d\n",
               (unsigned char)rule->destination_addresses[0], (unsigned char)rule->destination_addresses[1], (unsigned char)rule->destination_addresses[2], (unsigned char)rule->destination_addresses[3],
               (unsigned char)rule->destination_addresses[4], (unsigned char)rule->destination_addresses[5], (unsigned char)rule->destination_addresses[6], (unsigned char)rule->destination_addresses[7]);
        printf("Dest port: %d\n", rule->destination_port);
        printf("Protocol: %s\n", rule->proto == proto_TCP ? "TCP" : "UDP");
        printf("Action: %s\n", rule->action == proto_ACCEPT ? "ACCEPT" : "DROP");
        printf("Direction: %s\n", rule->direction == proto_INBOUND ? "INBOUND" : "OUTBOUND");
        printf("Enabled: %s\n", rule->enabled == proto_TRUE ? "true" : "false");
        free(rule);
    }
    else
    {
        printf("error parsing rule");
    }
    return 1;
}