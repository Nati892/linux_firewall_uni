#include "rule_tests.h"
#include <stdio.h>
int main(int argc, char **argv)
{
    printf("tests start\n");
    int rule_count = test_rule_count1();
    if (rule_count > 0)
    {
        printf("ok %d\n", rule_count);
    }
    else
    {
        printf("pak\n");
        return 1;
    }

    rule_count = test_rule_count2();
    if (rule_count > 0)
    {
        printf("ok %d\n", rule_count);
    }
    else
    {
        printf("pak\n");
        return 1;
    }

    const char *json_string = "{"
                              "\"id\": 0,"
                              "\"source_address\": \"0.0.0.0-255.255.255.254\","
                              "\"source_port\": \"0-65535\","
                              "\"destination_address\": \"0.0.0.0-255.255.255.255\","
                              "\"destination_port\": \"0-65535\","
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
               rule->source_addresses[0], rule->source_addresses[1], rule->source_addresses[2], rule->source_addresses[3],
               rule->source_addresses[4], rule->source_addresses[5], rule->source_addresses[6], rule->source_addresses[7]);
        printf("Source port: %d\n", rule->source_port);
        printf("Protocol: %s\n", rule->proto == proto_tcp ? "TCP" : "UDP");
        printf("Action: %s\n", rule->action == proto_TCP ? "ACCEPT" : "DROP");
        printf("Direction: %s\n", rule->direction == INBOUND ? "INBOUND" : "OUTBOUND");
        printf("Enabled: %s\n", rule->enabled == TRUE ? "true" : "false");
        free(rule);
    }
        return 0;
}
