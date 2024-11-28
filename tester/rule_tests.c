#include "rule_tests.h"

/*
void print_rule(fire_Rule *rule)
{

    if (rule == NULL)
    {
        return;
    }
    shared_print("Parsed rule ID: %d", rule->id);
    shared_print("Source address: %d.%d.%d.%d       \n",
           ((unsigned char*)&(rule->source_address))[0], ((unsigned char*)&(rule->source_address))[1], ((unsigned char*)&(rule->source_address))[2], ((unsigned char*)&(rule->source_address))[3]);
    shared_print("Source port: %d", rule->source_port);
    shared_print("Dest address: %d.%d.%d.%d       \n",
           ((unsigned char*)&(rule->destination_address))[0], ((unsigned char*)&(rule->destination_address))[1], ((unsigned char*)&(rule->destination_address))[2], ((unsigned char*)&(rule->destination_address))[3]);
    shared_print("Dest port: %d       \n", rule->destination_port);
    shared_print("Protocol: %s       \n", rule->proto == fire_proto_TCP ? "TCP" : "UDP");
    shared_print("Action: %s       \n", rule->action == fire_ACCEPT ? "ACCEPT" : "DROP");
    shared_print("Direction: %s       \n", rule->direction == fire_dir_INBOUND ? "INBOUND" : "OUTBOUND");
    shared_print("Enabled: %s         \n", rule->enabled == fire_TRUE ? "true" : "false");
}

int parse_test1()
{
    return GetRuleCount("{}{}{}", 6);
    return 1;
}

int parse_test2()
{
    return GetRuleCount("{}{}{}{}{}", 10);
    return 1;
}

int parse_test3()
{
    const char *json_string = "{"
                              "\"id\": 67,"
                              "\"source_address\": \"255.99.244.54\","
                              "\"source_port\": \"65535\","
                              "\"destination_address\": \"255.0.0.255\","
                              "\"destination_port\": \"9999\","
                              "\"protocol\": \"UDP\","
                              "\"action\": \"DROP\","
                              "\"direction\": \"OUTBOUND\","
                              "\"enabled\": false,"
                              "\"description\": \"\""
                              "}";

    fire_Rule rule = parse_json_to_rule((char *)json_string);
    if (rule.id != -1)
    {
      print_rule(&rule);
    }
    else
    {
        shared_print("error parsing rule");
        return -1;
    }
    return 1;
}

int parse_test4()
{
    const char *json_string = "["
                              "{"
                              "\"id\": 0,"
                              "\"source_address\": \"255.255.255.254\","
                              "\"source_port\": \"65535\","
                              "\"destination_address\": \"0.0.0.0\","
                              "\"destination_port\": \"666\","
                              "\"protocol\": \"TCP\","
                              "\"action\": \"ACCEPT\","
                              "\"direction\": \"INBOUND\","
                              "\"enabled\": true,"
                              "\"description\": \"\""
                              "},"
                              "{"
                              "\"id\": 1,"
                              "\"source_address\": \"0.99.0.0\","
                              "\"source_port\": \"65535\","
                              "\"destination_address\": \"255.255.255.255\","
                              "\"destination_port\": \"999\","
                              "\"protocol\": \"TCP\","
                              "\"action\": \"ACCEPT\","
                              "\"direction\": \"INBOUND\","
                              "\"enabled\": true,"
                              "\"description\": \"\""
                              "},"
                              "{"
                              "\"id\": 2,"
                              "\"source_address\": \"255.255.252.252\","
                              "\"source_port\": \"65535\","
                              "\"destination_address\": \"0.0.0.0\","
                              "\"destination_port\": \"888\","
                              "\"protocol\": \"TCP\","
                              "\"action\": \"ACCEPT\","
                              "\"direction\": \"OUTBOUND\","
                              "\"enabled\": true,"
                              "\"description\": \"\""
                              "}"
                              "]";
    int count = GetRuleCount((char *)json_string, strlen(json_string));
    shared_print("count is %d", count);
    if (count != 3)
    {
        shared_print("count is %d and not 3", count);
        return -1;
    }

    fire_Rule *list = parse_json_list((char *)json_string, count);
    if(list==NULL)
    return -1;

    return count;
}


int parse_test5()
{
    const char *json_string = "["
                              "{"
                              "\"id\": 0,"
                              "\"source_address\": \"255.255.255.254\","
                              "\"source_port\": \"65535\","
                              "\"destination_address\": \"0.1.2.3\","
                              "\"destination_port\": \"999\","
                              "\"protocol\": \"TCP\","
                              "\"action\": \"ACCEPT\","
                              "\"direction\": \"INBOUND\","
                              "\"enabled\": true,"
                              "\"description\": \"\""
                              "},"
                              "{"
                              "\"id\": 1,"
                              "\"source_address\": \"255.255.255.253\","
                              "\"source_port\": \"65535\","
                              "\"destination_address\": \"255.255.255.255\","
                              "\"destination_port\": \"666\","
                              "\"protocol\": \"TCP\","
                              "\"action\": \"ACCEPT\","
                              "\"direction\": \"INBOUND\","
                              "\"enabled\": true,"
                              "\"description\": \"\""
                              "},"
                              "{"
                              "\"id\": 2,"
                              "\"source_address\": \"255.255.255.252\","
                              "\"source_port\": \"65535\","
                              "\"destination_address\": \"0.0.0.0\","
                              "\"destination_port\": \"1\","
                              "\"protocol\": \"TCP\","
                              "\"action\": \"ACCEPT\","
                              "\"direction\": \"OUTBOUND\","
                              "\"enabled\": true,"
                              "\"description\": \"\""
                              "},"
                              "]";
    int count = GetRuleCount((char *)json_string, strlen(json_string));
    shared_print("count is %d", count);
    if (count != 3)
    {
        shared_print("count is %d and not 3", count);
        return -1;
    }

    fire_Rule *ptr = parse_json_list((char *)json_string, count);
    if (ptr == NULL)
    {
        shared_print("got NULL ptr from parse_json_list");
        return -1;
    }
    else
    {
        shared_free(ptr);
        return 1;
    }
}

int parse_test6()
{
    const char *json_string = "["
                              "{"
                              "\"id\": 0,"
                              "\"source_address\": \"123.255.255.254\","
                              "\"source_port\": \"80\","
                              "\"destination_address\": \"123.255.255.255\","
                              "\"destination_port\": \"876\","
                              "\"protocol\": \"TCP\","
                              "\"action\": \"ACCEPT\","
                              "\"direction\": \"OUTBOUND\","
                              "\"enabled\": true,"
                              "\"description\": \"\""
                              "},"
                              "{"
                              "\"id\": 1,"
                              "\"source_address\": \"231.255.255.253\","
                              "\"source_port\": \"65535\","
                              "\"destination_address\": \"142.255.255.255\","
                              "\"destination_port\": \"876\","
                              "\"protocol\": \"TCP\","
                              "\"action\": \"ACCEPT\","
                              "\"direction\": \"INBOUND\","
                              "\"enabled\": true,"
                              "\"description\": \"\""
                              "},"
                              "{"
                              "\"id\": 2,"
                              "\"source_address\": \"2.4.6.7\","
                              "\"source_port\": \"65535\","
                              "\"destination_address\": \"9.0.6.0\","
                              "\"destination_port\": \"765\","
                              "\"protocol\": \"TCP\","
                              "\"action\": \"ACCEPT\","
                              "\"direction\": \"INBOUND\","
                              "\"enabled\": true,"
                              "\"description\": \"\""
                              "},"
                              "{"
                              "\"id\": 3,"
                              "\"source_address\": \"9.7.5.3\","
                              "\"source_port\": \"567\","
                              "\"destination_address\": \"8.6.4.2\","
                              "\"destination_port\": \"999\","
                              "\"protocol\": \"TCP\","
                              "\"action\": \"ACCEPT\","
                              "\"direction\": \"OUTBOUND\","
                              "\"enabled\": true,"
                              "\"description\": \"\""
                              "},"
                              "{"
                              "\"id\": 4,"
                              "\"source_address\": \"77.66.55.44\","
                              "\"source_port\": \"65535\","
                              "\"destination_address\": \"44.55.66.77\","
                              "\"destination_port\": \"54312\","
                              "\"protocol\": \"TCP\","
                              "\"action\": \"ACCEPT\","
                              "\"direction\": \"INBOUND\","
                              "\"enabled\": true,"
                              "\"description\": \"\""
                              "},"
                              "{"
                              "\"id\": 5,"
                              "\"source_address\": \"255.255.255.252\","
                              "\"source_port\": \"65535\","
                              "\"destination_address\": \"0.0.0.0\","
                              "\"destination_port\": \"12345\","
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


int parse_test7()
{
    const char *json_string = "["
                              "{"
                              "\"id\": 0,"
                              "\"source_address\": \"0.99.0.0-255.255.257\","
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
    shared_print("count is %d", count);
    if (count != 3)
    {
        shared_print("count is %d and not 3", count);
        return -1;
    }

    fire_Rule *ptr = parse_json_list((char *)json_string, count);
    if (ptr == NULL)
    {
        shared_print("got NULL ptr from parse_json_list");
        return 1;
    }
    else
    {
        shared_free(ptr);
        return -1;
    }

    return count;
}

*/