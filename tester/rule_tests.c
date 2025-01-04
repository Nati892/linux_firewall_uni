#include "rule_tests.h"

#ifndef __KERNEL__
// Helper function to print rule details for debugging
void print_rule(fire_Rule *rule) {
    if (rule == NULL) {
        return;
    }
    shared_print("Rule ID: %d\n", rule->id);
    shared_print("Source address range: %u.%u.%u.%u - %u.%u.%u.%u\n",
           ((unsigned char*)&(rule->source_address_start))[0], ((unsigned char*)&(rule->source_address_start))[1],
           ((unsigned char*)&(rule->source_address_start))[2], ((unsigned char*)&(rule->source_address_start))[3],
           ((unsigned char*)&(rule->source_address_end))[0], ((unsigned char*)&(rule->source_address_end))[1],
           ((unsigned char*)&(rule->source_address_end))[2], ((unsigned char*)&(rule->source_address_end))[3]);
    shared_print("Source port range: %u - %u\n", rule->source_port_start, rule->source_port_end);
    shared_print("Destination address range: %u.%u.%u.%u - %u.%u.%u.%u\n",
           ((unsigned char*)&(rule->destination_address_start))[0], ((unsigned char*)&(rule->destination_address_start))[1],
           ((unsigned char*)&(rule->destination_address_start))[2], ((unsigned char*)&(rule->destination_address_start))[3],
           ((unsigned char*)&(rule->destination_address_end))[0], ((unsigned char*)&(rule->destination_address_end))[1],
           ((unsigned char*)&(rule->destination_address_end))[2], ((unsigned char*)&(rule->destination_address_end))[3]);
    shared_print("Destination port range: %u - %u\n", rule->destination_port_start, rule->destination_port_end);
    shared_print("Protocol: %s\n", rule->proto == fire_proto_TCP ? "TCP" : (rule->proto == fire_proto_UDP ? "UDP" : "ANY"));
    shared_print("Action: %s\n", rule->action == fire_ACCEPT ? "ACCEPT" : "DROP");
    shared_print("Direction: %s\n", rule->direction == fire_dir_INBOUND ? "INBOUND" : "OUTBOUND");
    shared_print("Enabled: %s\n", rule->enabled == fire_TRUE ? "true" : "false");
}

// Test 1: Test GetRuleCount with invalid JSON
int parse_test1() {
    const char *invalid_json = "{{}{}"; // Invalid JSON format
    int count = GetRuleCount((char*)invalid_json, strlen(invalid_json));
    return count == -1 ? 1 : -1; // Should return -1 for invalid JSON
}

// Test 2: Test GetRuleCount with valid JSON
int parse_test2() {
    const char *valid_json = "[{\"id\":1},{\"id\":2},{\"id\":3}]";
    int count = GetRuleCount((char*)valid_json, strlen(valid_json));
    return count == 3 ? 1 : -1;
}

// Test 3: Test parsing IP range
int parse_test3() {
    SHARED_UINT32 start_ip, end_ip;
    const char *ip_range = "192.168.1.1-192.168.1.10";
    int result = parse_ip_range(ip_range, &start_ip, &end_ip);
    if (result != 0) return -1;
    
    // Verify the parsed range
    unsigned char *start = (unsigned char*)&start_ip;
    unsigned char *end = (unsigned char*)&end_ip;
    if (start[0] != 192 || start[1] != 168 || start[2] != 1 || start[3] != 1) return -1;
    if (end[0] != 192 || end[1] != 168 || end[2] != 1 || end[3] != 10) return -1;
    
    return 1;
}

// Test 4: Test parsing port range
int parse_test4() {
    uint32_t start_port, end_port;
    const char *port_range = "80-443";
    int result = parse_port_range(port_range, &start_port, &end_port);
    if (result != 0) return -1;
    
    if (start_port != 80 || end_port != 443) return -1;
    return 1;
}

// Test 5: Test ParseRules with complete rule set
int parse_test5() {
    const char *json_string = "[{"
        "\"id\": 0,"
        "\"source_address_start\": \"192.168.1.1\","
        "\"source_address_end\": \"192.168.1.10\","
        "\"source_port_start\": \"80\","
        "\"source_port_end\": \"80\","
        "\"destination_address_start\": \"10.0.0.1\","
        "\"destination_address_end\": \"10.0.0.10\","
        "\"destination_port_start\": \"443\","
        "\"destination_port_end\": \"443\","
        "\"protocol\": \"TCP\","
        "\"action\": \"ACCEPT\","
        "\"direction\": \"INBOUND\","
        "\"enabled\": true"
    "}]";

    fire_Rule *inbound = NULL;
    fire_Rule *outbound = NULL;
    int inbound_count = 0;
    int outbound_count = 0;

    fire_BOOL result = ParseRules((char*)json_string, strlen(json_string), 
                                &inbound, &inbound_count,
                                &outbound, &outbound_count);
    
    if (result != fire_TRUE) return -1;
    if (inbound_count != 1 || outbound_count != 0) return -1;
    
    if (inbound != NULL) {
        print_rule(&inbound[0]);
        shared_free(inbound);
    }
    if (outbound != NULL) {
        shared_free(outbound);
    }
    
    return 1;
}

// Test 6: Test rule parsing with invalid values
int parse_test6() {
    const char *invalid_json = "{"
        "\"id\": 0,"
        "\"source_address_start\": \"256.168.1.1\"," // Invalid IP
        "\"source_address_end\": \"192.168.1.10\","
        "\"source_port_start\": \"80\","
        "\"source_port_end\": \"80\","
        "\"destination_address_start\": \"10.0.0.1\","
        "\"destination_address_end\": \"10.0.0.10\","
        "\"destination_port_start\": \"443\","
        "\"destination_port_end\": \"443\","
        "\"protocol\": \"TCP\","
        "\"action\": \"ACCEPT\","
        "\"direction\": \"INBOUND\","
        "\"enabled\": true"
    "}";

    fire_Rule rule = parse_json_to_rule((char*)invalid_json);
    return rule.id == -1 ? 1 : -1; // Should fail with invalid IP
}

// Test 7: Test parsing multiple rules with mixed directions
int parse_test7() {
    const char *json_string = "[{"
        "\"id\": 0,"
        "\"source_address_start\": \"192.168.1.1\","
        "\"source_address_end\": \"192.168.1.10\","
        "\"source_port_start\": \"80\","
        "\"source_port_end\": \"80\","
        "\"destination_address_start\": \"10.0.0.1\","
        "\"destination_address_end\": \"10.0.0.10\","
        "\"destination_port_start\": \"443\","
        "\"destination_port_end\": \"443\","
        "\"protocol\": \"TCP\","
        "\"action\": \"ACCEPT\","
        "\"direction\": \"INBOUND\","
        "\"enabled\": true"
    "},{"
        "\"id\": 1,"
        "\"source_address_start\": \"10.0.0.1\","
        "\"source_address_end\": \"10.0.0.10\","
        "\"source_port_start\": \"443\","
        "\"source_port_end\": \"443\","
        "\"destination_address_start\": \"192.168.1.1\","
        "\"destination_address_end\": \"192.168.1.10\","
        "\"destination_port_start\": \"80\","
        "\"destination_port_end\": \"80\","
        "\"protocol\": \"TCP\","
        "\"action\": \"ACCEPT\","
        "\"direction\": \"OUTBOUND\","
        "\"enabled\": true"
    "}]";

    fire_Rule *inbound = NULL;
    fire_Rule *outbound = NULL;
    int inbound_count = 0;
    int outbound_count = 0;

    fire_BOOL result = ParseRules((char*)json_string, strlen(json_string), 
                                &inbound, &inbound_count,
                                &outbound, &outbound_count);
    
    if (result != fire_TRUE) return -1;
    if (inbound_count != 1 || outbound_count != 1) return -1;
    
    if (inbound != NULL) {
        print_rule(&inbound[0]);
        shared_free(inbound);
    }
    if (outbound != NULL) {
        print_rule(&outbound[0]);
        shared_free(outbound);
    }
    
    return 1;
}


// Test 1: Basic single rule test - Tests basic port forwarding rule
int parse_test8() {
    const char *json = "{"
        "\"id\": 1,"
        "\"source_address_start\": \"192.168.1.1\","
        "\"source_address_end\": \"192.168.1.1\","
        "\"source_port_start\": \"80\","
        "\"source_port_end\": \"80\","
        "\"destination_address_start\": \"10.0.0.1\","
        "\"destination_address_end\": \"10.0.0.1\","
        "\"destination_port_start\": \"8080\","
        "\"destination_port_end\": \"8080\","
        "\"protocol\": \"TCP\","
        "\"action\": \"ACCEPT\","
        "\"direction\": \"INBOUND\","
        "\"enabled\": true"
    "}";
    
    fire_Rule rule = parse_json_to_rule((char*)json);
    if (rule.id != 1) return -1;
    if (rule.source_port_start != 80) return -1;
    if (rule.destination_port_start != 8080) return -1;
    return 1;
}

// Test 2: Full subnet range test - Tests handling of wide IP ranges
int parse_test9() {
    const char *json = "{"
        "\"id\": 2,"
        "\"source_address_start\": \"192.168.0.0\","
        "\"source_address_end\": \"192.168.255.255\","
        "\"source_port_start\": \"0\","
        "\"source_port_end\": \"65535\","
        "\"destination_address_start\": \"10.0.0.0\","
        "\"destination_address_end\": \"10.255.255.255\","
        "\"destination_port_start\": \"0\","
        "\"destination_port_end\": \"65535\","
        "\"protocol\": \"ANY\","
        "\"action\": \"ACCEPT\","
        "\"direction\": \"OUTBOUND\","
        "\"enabled\": true"
    "}";
    
    fire_Rule rule = parse_json_to_rule((char*)json);
    if (rule.id != 2) return -1;
    if (rule.proto != fire_proto_ANY) return -1;
    if (rule.source_port_end != 65535) return -1;
    return 1;
}

// Test 3: Multiple protocol test - Tests typical web server configuration
int parse_test10() {
    const char *json = "["
        "{"
            "\"id\": 3,"
            "\"source_address_start\": \"0.0.0.0\","
            "\"source_address_end\": \"255.255.255.255\","
            "\"source_port_start\": \"0\","
            "\"source_port_end\": \"65535\","
            "\"destination_address_start\": \"192.168.1.100\","
            "\"destination_address_end\": \"192.168.1.100\","
            "\"destination_port_start\": \"80\","
            "\"destination_port_end\": \"80\","
            "\"protocol\": \"TCP\","
            "\"action\": \"ACCEPT\","
            "\"direction\": \"INBOUND\","
            "\"enabled\": true"
        "},"
        "{"
            "\"id\": 4,"
            "\"source_address_start\": \"0.0.0.0\","
            "\"source_address_end\": \"255.255.255.255\","
            "\"source_port_start\": \"0\","
            "\"source_port_end\": \"65535\","
            "\"destination_address_start\": \"192.168.1.100\","
            "\"destination_address_end\": \"192.168.1.100\","
            "\"destination_port_start\": \"443\","
            "\"destination_port_end\": \"443\","
            "\"protocol\": \"TCP\","
            "\"action\": \"ACCEPT\","
            "\"direction\": \"INBOUND\","
            "\"enabled\": true"
        "}"
    "]";

    fire_Rule *inbound = NULL;
    fire_Rule *outbound = NULL;
    int inbound_count = 0;
    int outbound_count = 0;

    fire_BOOL result = ParseRules((char*)json, strlen(json), 
                                &inbound, &inbound_count,
                                &outbound, &outbound_count);
    
    if (!result) return -1;
    if (inbound_count != 2) return -1;
    if (outbound_count != 0) return -1;

    shared_free(inbound);
    shared_free(outbound);
    return 1;
}

// Test 4: DNS Server configuration test
int parse_test11() {
    const char *json = "{"
        "\"id\": 5,"
        "\"source_address_start\": \"0.0.0.0\","
        "\"source_address_end\": \"255.255.255.255\","
        "\"source_port_start\": \"0\","
        "\"source_port_end\": \"65535\","
        "\"destination_address_start\": \"192.168.1.53\","
        "\"destination_address_end\": \"192.168.1.53\","
        "\"destination_port_start\": \"53\","
        "\"destination_port_end\": \"53\","
        "\"protocol\": \"UDP\","
        "\"action\": \"ACCEPT\","
        "\"direction\": \"INBOUND\","
        "\"enabled\": true"
    "}";
    
    fire_Rule rule = parse_json_to_rule((char*)json);
    if (rule.id != 5) return -1;
    if (rule.proto != fire_proto_UDP) return -1;
    if (rule.destination_port_start != 53) return -1;
    return 1;
}

// Test 5: VPN Server configuration test
int parse_test12() {
    const char *json = "{"
        "\"id\": 6,"
        "\"source_address_start\": \"0.0.0.0\","
        "\"source_address_end\": \"255.255.255.255\","
        "\"source_port_start\": \"0\","
        "\"source_port_end\": \"65535\","
        "\"destination_address_start\": \"192.168.1.1\","
        "\"destination_address_end\": \"192.168.1.1\","
        "\"destination_port_start\": \"1194\","
        "\"destination_port_end\": \"1194\","
        "\"protocol\": \"UDP\","
        "\"action\": \"ACCEPT\","
        "\"direction\": \"INBOUND\","
        "\"enabled\": true"
    "}";
    
    fire_Rule rule = parse_json_to_rule((char*)json);
    if (rule.id != 6) return -1;
    if (rule.proto != fire_proto_UDP) return -1;
    if (rule.destination_port_start != 1194) return -1;
    return 1;
}

// Test 6: Mail server configuration test
int parse_test13() {
    const char *json = "["
        "{"
            "\"id\": 7,"
            "\"source_address_start\": \"0.0.0.0\","
            "\"source_address_end\": \"255.255.255.255\","
            "\"source_port_start\": \"0\","
            "\"source_port_end\": \"65535\","
            "\"destination_address_start\": \"192.168.1.25\","
            "\"destination_address_end\": \"192.168.1.25\","
            "\"destination_port_start\": \"25\","
            "\"destination_port_end\": \"25\","
            "\"protocol\": \"TCP\","
            "\"action\": \"ACCEPT\","
            "\"direction\": \"INBOUND\","
            "\"enabled\": true"
        "},"
        "{"
            "\"id\": 8,"
            "\"source_address_start\": \"0.0.0.0\","
            "\"source_address_end\": \"255.255.255.255\","
            "\"source_port_start\": \"0\","
            "\"source_port_end\": \"65535\","
            "\"destination_address_start\": \"192.168.1.25\","
            "\"destination_address_end\": \"192.168.1.25\","
            "\"destination_port_start\": \"587\","
            "\"destination_port_end\": \"587\","
            "\"protocol\": \"TCP\","
            "\"action\": \"ACCEPT\","
            "\"direction\": \"INBOUND\","
            "\"enabled\": true"
        "}"
    "]";

    fire_Rule *inbound = NULL;
    fire_Rule *outbound = NULL;
    int inbound_count = 0;
    int outbound_count = 0;

    fire_BOOL result = ParseRules((char*)json, strlen(json), 
                                &inbound, &inbound_count,
                                &outbound, &outbound_count);
    
    if (!result) return -1;
    if (inbound_count != 2) return -1;
    if (outbound_count != 0) return -1;

    shared_free(inbound);
    shared_free(outbound);
    return 1;
}

// Test 7: SSH and RDP access test
int parse_test14() {
    const char *json = "["
        "{"
            "\"id\": 9,"
            "\"source_address_start\": \"192.168.1.0\","
            "\"source_address_end\": \"192.168.1.255\","
            "\"source_port_start\": \"0\","
            "\"source_port_end\": \"65535\","
            "\"destination_address_start\": \"10.0.0.0\","
            "\"destination_address_end\": \"10.0.0.255\","
            "\"destination_port_start\": \"22\","
            "\"destination_port_end\": \"22\","
            "\"protocol\": \"TCP\","
            "\"action\": \"ACCEPT\","
            "\"direction\": \"OUTBOUND\","
            "\"enabled\": true"
        "},"
        "{"
            "\"id\": 10,"
            "\"source_address_start\": \"192.168.1.0\","
            "\"source_address_end\": \"192.168.1.255\","
            "\"source_port_start\": \"0\","
            "\"source_port_end\": \"65535\","
            "\"destination_address_start\": \"10.0.0.0\","
            "\"destination_address_end\": \"10.0.0.255\","
            "\"destination_port_start\": \"3389\","
            "\"destination_port_end\": \"3389\","
            "\"protocol\": \"TCP\","
            "\"action\": \"ACCEPT\","
            "\"direction\": \"OUTBOUND\","
            "\"enabled\": true"
        "}"
    "]";

    fire_Rule *inbound = NULL;
    fire_Rule *outbound = NULL;
    int inbound_count = 0;
    int outbound_count = 0;

    fire_BOOL result = ParseRules((char*)json, strlen(json), 
                                &inbound, &inbound_count,
                                &outbound, &outbound_count);
    
    if (!result) return -1;
    if (inbound_count != 0) return -1;
    if (outbound_count != 2) return -1;

    shared_free(inbound);
    shared_free(outbound);
    return 1;
}
// Test 15: Invalid IP address format
int parse_test15() {
    const char *json = "{"
        "\"id\": 1,"
        "\"source_address_start\": \"256.168.1.1\"," // Invalid IP (256 is out of range)
        "\"source_address_end\": \"192.168.1.1\","
        "\"source_port_start\": \"80\","
        "\"source_port_end\": \"80\","
        "\"destination_address_start\": \"10.0.0.1\","
        "\"destination_address_end\": \"10.0.0.1\","
        "\"destination_port_start\": \"8080\","
        "\"destination_port_end\": \"8080\","
        "\"protocol\": \"TCP\","
        "\"action\": \"ACCEPT\","
        "\"direction\": \"INBOUND\","
        "\"enabled\": true"
    "}";
    
    fire_Rule rule = parse_json_to_rule((char*)json);
    return (rule.id == -1) ? 1 : -1; // Should fail with invalid IP
}

// Test 16: Invalid port range (end < start)
int parse_test16() {
    const char *json = "{"
        "\"id\": 1,"
        "\"source_address_start\": \"192.168.1.1\","
        "\"source_address_end\": \"192.168.1.1\","
        "\"source_port_start\": \"8080\"," // Port range is invalid (end < start)
        "\"source_port_end\": \"80\","
        "\"destination_address_start\": \"10.0.0.1\","
        "\"destination_address_end\": \"10.0.0.1\","
        "\"destination_port_start\": \"8080\","
        "\"destination_port_end\": \"8080\","
        "\"protocol\": \"TCP\","
        "\"action\": \"ACCEPT\","
        "\"direction\": \"INBOUND\","
        "\"enabled\": true"
    "}";
    
    fire_Rule rule = parse_json_to_rule((char*)json);
    return (rule.id == -1) ? 1 : -1; // Should fail with invalid port range
}

// Test 17: Invalid JSON structure (missing closing brace)
int parse_test17() {
    const char *json = "{"
        "\"id\": 1,"
        "\"source_address_start\": \"192.168.1.1\","
        "\"source_address_end\": \"192.168.1.1\","
        "\"source_port_start\": \"80\","
        "\"source_port_end\": \"80\","
        "\"protocol\": \"TCP\"," // Missing several required fields
        "\"enabled\": true" // Missing closing brace
    ;
    
    fire_Rule rule = parse_json_to_rule((char*)json);
    return (rule.id == -1) ? 1 : -1; // Should fail with invalid JSON
}

// Test 18: Invalid protocol value
int parse_test18() {
    const char *json = "{"
        "\"id\": 1,"
        "\"source_address_start\": \"192.168.1.1\","
        "\"source_address_end\": \"192.168.1.1\","
        "\"source_port_start\": \"80\","
        "\"source_port_end\": \"80\","
        "\"destination_address_start\": \"10.0.0.1\","
        "\"destination_address_end\": \"10.0.0.1\","
        "\"destination_port_start\": \"8080\","
        "\"destination_port_end\": \"8080\","
        "\"protocol\": \"INVALID_PROTOCOL\"," // Invalid protocol
        "\"action\": \"ACCEPT\","
        "\"direction\": \"INBOUND\","
        "\"enabled\": true"
    "}";
    
    fire_Rule rule = parse_json_to_rule((char*)json);
    return (rule.id == -1) ? 1 : -1; // Should fail with invalid protocol
}

// Test 19: Invalid IP range (end < start)
int parse_test19() {
    const char *json = "{"
        "\"id\": 1,"
        "\"source_address_start\": \"192.168.1.10\"," // Start IP greater than end IP
        "\"source_address_end\": \"192.168.1.1\","
        "\"source_port_start\": \"80\","
        "\"source_port_end\": \"80\","
        "\"destination_address_start\": \"10.0.0.1\","
        "\"destination_address_end\": \"10.0.0.1\","
        "\"destination_port_start\": \"8080\","
        "\"destination_port_end\": \"8080\","
        "\"protocol\": \"TCP\","
        "\"action\": \"ACCEPT\","
        "\"direction\": \"INBOUND\","
        "\"enabled\": true"
    "}";
    
    fire_Rule rule = parse_json_to_rule((char*)json);
    return (rule.id == -1) ? 1 : -1; // Should fail with invalid IP range
}

// Test 20: Invalid action value
int parse_test20() {
    const char *json = "{"
        "\"id\": 1,"
        "\"source_address_start\": \"192.168.1.1\","
        "\"source_address_end\": \"192.168.1.1\","
        "\"source_port_start\": \"80\","
        "\"source_port_end\": \"80\","
        "\"destination_address_start\": \"10.0.0.1\","
        "\"destination_address_end\": \"10.0.0.1\","
        "\"destination_port_start\": \"8080\","
        "\"destination_port_end\": \"8080\","
        "\"protocol\": \"TCP\","
        "\"action\": \"INVALID_ACTION\"," // Invalid action
        "\"direction\": \"INBOUND\","
        "\"enabled\": true"
    "}";
    
    fire_Rule rule = parse_json_to_rule((char*)json);
    return (rule.id == -1) ? 1 : -1; // Should fail with invalid action
}

// Test 21: Invalid direction value
int parse_test21() {
    const char *json = "{"
        "\"id\": 1,"
        "\"source_address_start\": \"192.168.1.1\","
        "\"source_address_end\": \"192.168.1.1\","
        "\"source_port_start\": \"80\","
        "\"source_port_end\": \"80\","
        "\"destination_address_start\": \"10.0.0.1\","
        "\"destination_address_end\": \"10.0.0.1\","
        "\"destination_port_start\": \"8080\","
        "\"destination_port_end\": \"8080\","
        "\"protocol\": \"TCP\","
        "\"action\": \"ACCEPT\","
        "\"direction\": \"SIDEWAYS\"," // Invalid direction
        "\"enabled\": true"
    "}";
    
    fire_Rule rule = parse_json_to_rule((char*)json);
    return (rule.id == -1) ? 1 : -1; // Should fail with invalid direction
}

// Test 22: Invalid port number (out of range)
int parse_test22() {
    const char *json = "{"
        "\"id\": 1,"
        "\"source_address_start\": \"192.168.1.1\","
        "\"source_address_end\": \"192.168.1.1\","
        "\"source_port_start\": \"65536\"," // Invalid port number (> 65535)
        "\"source_port_end\": \"65536\","
        "\"destination_address_start\": \"10.0.0.1\","
        "\"destination_address_end\": \"10.0.0.1\","
        "\"destination_port_start\": \"8080\","
        "\"destination_port_end\": \"8080\","
        "\"protocol\": \"TCP\","
        "\"action\": \"ACCEPT\","
        "\"direction\": \"INBOUND\","
        "\"enabled\": true"
    "}";
    
    fire_Rule rule = parse_json_to_rule((char*)json);
    return (rule.id == -1) ? 1 : -1; // Should fail with invalid port number
}
int RunTests() {
    shared_print("Starting Rule Parser Tests\n");
    fire_BOOL all_passed = fire_TRUE;
    int result;

    shared_print("\nTest 1: Invalid JSON count check\n");
    result = parse_test1();
    if (result > 0) {
        shared_print("Test 1 PASSED\n");
    } else {
        shared_print("Test 1 FAILED\n");
        all_passed = fire_FALSE;
    }

    shared_print("\nTest 2: Valid JSON count check\n");
    result = parse_test2();
    if (result > 0) {
        shared_print("Test 2 PASSED\n");
    } else {
        shared_print("Test 2 FAILED\n");
        all_passed = fire_FALSE;
    }

    shared_print("\nTest 3: IP range parsing\n");
    result = parse_test3();
    if (result > 0) {
        shared_print("Test 3 PASSED\n");
    } else {
        shared_print("Test 3 FAILED\n");
        all_passed = fire_FALSE;
    }

    shared_print("\nTest 4: Port range parsing\n");
    result = parse_test4();
    if (result > 0) {
        shared_print("Test 4 PASSED\n");
    } else {
        shared_print("Test 4 FAILED\n");
        all_passed = fire_FALSE;
    }

    shared_print("\nTest 5: Complete rule parsing\n");
    result = parse_test5();
    if (result > 0) {
        shared_print("Test 5 PASSED\n");
    } else {
        shared_print("Test 5 FAILED\n");
        all_passed = fire_FALSE;
    }

    shared_print("\nTest 6: Invalid rule values\n");
    result = parse_test6();
    if (result > 0) {
        shared_print("Test 6 PASSED\n");
    } else {
        shared_print("Test 6 FAILED\n");
        all_passed = fire_FALSE;
    }

    shared_print("\nTest 7\n");
    result = parse_test7();
    if (result > 0) {
        shared_print("Test 7 PASSED\n");
    } else {
        shared_print("Test 7 FAILED\n");
        all_passed = fire_FALSE;
    }

    shared_print("\nTest 8\n");
    result = parse_test8();
    if (result > 0) {
        shared_print("Test 8 PASSED\n");
    } else {
        shared_print("Test 8 FAILED\n");
        all_passed = fire_FALSE;
    }

    shared_print("\nTest 9\n");
    result = parse_test9();
    if (result > 0) {
        shared_print("Test 9 PASSED\n");
    } else {
        shared_print("Test 9 FAILED\n");
        all_passed = fire_FALSE;
    }

    shared_print("\nTest 10\n");
    result = parse_test10();
    if (result > 0) {
        shared_print("Test 10 PASSED\n");
    } else {
        shared_print("Test 10 FAILED\n");
        all_passed = fire_FALSE;
    }

    shared_print("\nTest 11\n");
    result = parse_test11();
    if (result > 0) {
        shared_print("Test 11 PASSED\n");
    } else {
        shared_print("Test 11 FAILED\n");
        all_passed = fire_FALSE;
    }

    shared_print("\nTest 12\n");
    result = parse_test12();
    if (result > 0) {
        shared_print("Test 12 PASSED\n");
    } else {
        shared_print("Test 12 FAILED\n");
        all_passed = fire_FALSE;
    }

    shared_print("\nTest 13\n");
    result = parse_test13();
    if (result > 0) {
        shared_print("Test 13 PASSED\n");
    } else {
        shared_print("Test 13 FAILED\n");
        all_passed = fire_FALSE;
    }

    shared_print("\nTest 14\n");
    result = parse_test14();
    if (result > 0) {
        shared_print("Test 14 PASSED\n");
    } else {
        shared_print("Test 14 FAILED\n");
        all_passed = fire_FALSE;
    }
shared_print("\nTest 15: Testing invalid IP address format\n");
    result = parse_test15();
    if (result > 0) {
        shared_print("Test 15 PASSED\n");
    } else {
        shared_print("Test 15 FAILED\n");
        all_passed = fire_FALSE;
    }

    shared_print("\nTest 16: Testing invalid port range\n");
    result = parse_test16();
    if (result > 0) {
        shared_print("Test 16 PASSED\n");
    } else {
        shared_print("Test 16 FAILED\n");
        all_passed = fire_FALSE;
    }

    shared_print("\nTest 17: Testing malformed JSON\n");
    result = parse_test17();
    if (result > 0) {
        shared_print("Test 17 PASSED\n");
    } else {
        shared_print("Test 17 FAILED\n");
        all_passed = fire_FALSE;
    }

    shared_print("\nTest 18: Testing invalid protocol value\n");
    result = parse_test18();
    if (result > 0) {
        shared_print("Test 18 PASSED\n");
    } else {
        shared_print("Test 18 FAILED\n");
        all_passed = fire_FALSE;
    }

    shared_print("\nTest 19: Testing invalid IP range\n");
    result = parse_test19();
    if (result > 0) {
        shared_print("Test 19 PASSED\n");
    } else {
        shared_print("Test 19 FAILED\n");
        all_passed = fire_FALSE;
    }

    shared_print("\nTest 20: Testing invalid action value\n");
    result = parse_test20();
    if (result > 0) {
        shared_print("Test 20 PASSED\n");
    } else {
        shared_print("Test 20 FAILED\n");
        all_passed = fire_FALSE;
    }

    shared_print("\nTest 21: Testing invalid direction value\n");
    result = parse_test21();
    if (result > 0) {
        shared_print("Test 21 PASSED\n");
    } else {
        shared_print("Test 21 FAILED\n");
        all_passed = fire_FALSE;
    }

    shared_print("\nTest 22: Testing invalid port number\n");
    result = parse_test22();
    if (result > 0) {
        shared_print("Test 22 PASSED\n");
    } else {
        shared_print("Test 22 FAILED\n");
        all_passed = fire_FALSE;
    }
    if (all_passed) {
        shared_print("\nAll tests PASSED!\n");
        return 0;
    } else {
        shared_print("\nSome tests FAILED!\n");
        return 1;
    }
}
#else
int RunTests() {return 0;}
#endif