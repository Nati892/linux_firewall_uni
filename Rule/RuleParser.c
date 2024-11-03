#include "RuleParser.h"

int GetRuleCount(char *in_json, int length)
{
    int count = 0;
    int i = 0;

    fire_BOOL in_opening_brackets = fire_FALSE;
    while (*in_json != '\0' && i < length)
    {
        if (*in_json == '{' && in_opening_brackets == fire_FALSE)
        {
            in_opening_brackets = fire_TRUE;
            count++;
        }
        else if (*in_json == '{' && in_opening_brackets == fire_TRUE) // report error
        {
            return -1;
        }

        if (*in_json == '}' && in_opening_brackets == fire_TRUE)
        {
            in_opening_brackets = fire_FALSE;
        }
        else if (*in_json == '}' && in_opening_brackets == fire_FALSE) // report error
        {
            return -1;
        }

        in_json++;
        i++;
    }

    return count;
}

fire_BOOL ParseRules(char *in_json,
                     int length,
                     fire_Rule **rule_table_inbound, int *table_size_inbound,
                     fire_Rule **rule_table_outbound, int *table_size_outbound)
{
    // Initialize counts for inbound and outbound rules
    int inbound_count = 0;
    int outbound_count = 0;

    // Count the total number of rules in JSON input
    int rule_count = GetRuleCount(in_json, length);
    if (rule_count < 0)
    {
        shared_print("Error: Could not count rules in JSON");
        return fire_FALSE;
    }

    // Parse JSON input into a temporary list of rules
    fire_Rule *parsed_rules = parse_json_list(in_json, rule_count);
    if (parsed_rules == NULL)
    {
        shared_print("Error: Failed to parse JSON input");
        return fire_FALSE;
    }

    // First pass: Count inbound and outbound rules
    for (int i = 0; i < rule_count; i++)
    {
        if (parsed_rules[i].direction == fire_dir_INBOUND)
        {
            inbound_count++;
        }
        else if (parsed_rules[i].direction == fire_dir_OUTBOUND)
        {
            outbound_count++;
        }
        else
        {
            shared_print("Error: Invalid rule direction");
            shared_free(parsed_rules);
            return fire_FALSE;
        }
    }

    // Allocate memory for inbound and outbound rule tables based on counts
    *rule_table_inbound = (fire_Rule *)shared_malloc(inbound_count * sizeof(fire_Rule));
    *rule_table_outbound = (fire_Rule *)shared_malloc(outbound_count * sizeof(fire_Rule));

    // Check if allocations were successful
    if (*rule_table_inbound == NULL || *rule_table_outbound == NULL)
    {
        shared_print("Error: Memory allocation failed");
        shared_free(parsed_rules);
        if (*rule_table_inbound)
            shared_free(*rule_table_inbound);
        if (*rule_table_outbound)
            shared_free(*rule_table_outbound);
        return fire_FALSE;
    }

    // Second pass: Populate inbound and outbound tables
    int inbound_index = 0;
    int outbound_index = 0;
    for (int i = 0; i < rule_count; i++)
    {
        if (parsed_rules[i].direction == fire_dir_INBOUND)
        {
            (*rule_table_inbound)[inbound_index++] = parsed_rules[i];
        }
        else if (parsed_rules[i].direction == fire_dir_OUTBOUND)
        {
            (*rule_table_outbound)[outbound_index++] = parsed_rules[i];
        }
    }

    // Set the table sizes
    *table_size_inbound = inbound_count;
    *table_size_outbound = outbound_count;

    // shared_free the temporary parsed rules array
    shared_free(parsed_rules);

    // Return success after populating both tables
    return fire_TRUE;
}

SHARED_UINT32 char_array_to_u32(const char ip[4])
{
    // Combine bytes into a __u32
    return ((SHARED_UINT32)(unsigned char)ip[0] << 24) |
           ((SHARED_UINT32)(unsigned char)ip[1] << 16) |
           ((SHARED_UINT32)(unsigned char)ip[2] << 8) |
           ((SHARED_UINT32)(unsigned char)ip[3]);
}

// Helper function to safely copy strings
size_t safe_strcpy(char *dest, size_t destsize, const char *src)
{
    size_t len = strlen(src);
    if (len >= destsize)
    {
        len = destsize - 1;
    }
    memcpy(dest, src, len);
    dest[len] = '\0';
    return len;
}
#ifndef __KERNEL__
// Helper function to parse a single integer
int parse_int(const char *str)
{
    char *endptr;
    errno = 0;
    long val = strtol(str, &endptr, 10);

    if (errno != 0 || endptr == str || *endptr != '\0' || val > INT_MAX || val < INT_MIN)
    {
        shared_print("error parsing int");
        return -1; // Return 0 on error
    }

    return (int)val;
}
#else

// Helper function to parse a single integer
int parse_int(const char *str)
{
    char *endptr;
    long val;

    // Use simple_strtol for kernel space
    val = simple_strtol(str, &endptr, 10);

    // Check for errors
    if (endptr == str || *endptr != '\0' || val > INT_MAX || val < INT_MIN)
    {
        shared_print(KERN_ERR "error parsing int: invalid input '%s'", str);
        return -1; // Return -EINVAL for invalid argument
    }

    return (int)val;
}


#endif

#ifndef __KERNEL__
// Helper function to parse IP address
int parse_ip(const char *ip, char *output)
{
    char *token;
    char *rest = strdup(ip);
    char *ptr = rest;
    int i = 0;

    while ((token = strtok_r(ptr, ".", &ptr)))
    {
        if (i < 4)
        {
            int res = parse_int(token);
            if (res < 0 || res > 255)
            {
                shared_free(rest);
                return -1;
            }
            if (res < -1)
            {
                shared_free(rest);
                return -1;
            }
            output[i] = (char)res;
        }
        i++;
    }

    shared_free(rest);
    return 0;
}
#else

int parse_ip(const char *ip, u8 *output)
{
    char *rest;
    char *temp;
    int res;
    
    // Validate input
    if (!ip || !output)
        return -EINVAL; // Return -EINVAL for invalid argument

    // Duplicate the string using kstrdup
    temp = kstrdup(ip, GFP_KERNEL);
    if (!temp)
        return -ENOMEM; // Return -ENOMEM for memory allocation failure

    // Use strtok to tokenize the string
    rest = temp;
    for (int i = 0; i < 4; i++) {
        char *token = strsep(&rest, ".");
        
        if (!token) {
            shared_free(temp); // Free allocated memory before returning
            return -EINVAL; // Return -EINVAL for incorrect format
        }

        res = parse_int(token);
        if (res < 0 || res > 255) {
            shared_free(temp);
            return -1; // Invalid value
        }
        output[i] = (u8)res; // Store the result in the output array
    }

    shared_free(temp); // Free allocated memory
    return 0; // Success
}

#endif

#ifndef __KERNEL__
// Helper function to parse port range
int parse_port_range(const char *port_str)
{
    char port[MAX_PORT_LENGTH];
    strncpy(port, port_str, MAX_PORT_LENGTH - 1);
    port[MAX_PORT_LENGTH - 1] = '\0';

    // Convert the port string to an integer and validate
    int port_num = atoi(port);

    if (port_num < 0 || port_num > 65535)
    {
        return -1; // Invalid port
    }

    return port_num; // Return the validated port
}

#else
// Helper function to parse port range
int parse_port_range(const char *port_str)
{
    char port[MAX_PORT_LENGTH];
    strncpy(port, port_str, MAX_PORT_LENGTH - 1);
    port[MAX_PORT_LENGTH - 1] = '\0';  // Ensure null-termination

    // Convert the port string to an integer and validate
    char *endptr;
    unsigned long port_num = simple_strtoul(port, &endptr, 10);

    // Check if the conversion was successful and if we parsed the whole string
    if (*endptr != '\0' || port_num > 65535)
    {
        return -1; // Invalid port
    }

    return (int)port_num; // Return the validated port
}
#endif

// Assuming shared_malloc and safe_strcpy are defined elsewhere

char *extract_value(const char *json, const char *key)
{
    char search_key[256];
    // Format the search key to match the JSON key format
    snprintf(search_key, sizeof(search_key), "\"%s\":", key);

    const char *start = strstr(json, search_key);
    if (start == NULL)
        return NULL;

    start += strlen(search_key);
    while (isspace(*start))
        start++;

    const char *end;
    if (*start == '"')
    {
        start++;
        end = strchr(start, '"');
    }
    else if (*start == '{' || *start == '[')
    {
        int count = 1;
        end = start + 1;
        while (count > 0 && *end)
        {
            if (*end == '{' || *end == '[')
                count++;
            if (*end == '}' || *end == ']')
                count--;
            end++;
        }
    }
    else
    {
        end = start;
        while (*end && *end != ',' && *end != '}')
            end++;
    }

    if (end == NULL)
        return NULL;

    size_t length = end - start;
    char *value = (char *)shared_malloc(length + 1);
    if (value == NULL)
        return NULL;

    // Use a safe string copy function
    safe_strcpy(value, length + 1, start);
    value[length] = '\0'; // Null-terminate the value

    return value;
}


// Function to parse the list of JSON-like objects
fire_Rule *parse_json_list(char *input, int count)
{
    char *p = input;
    int rule_index = 0;
    fire_Rule *rule_array = (fire_Rule *)shared_malloc(sizeof(fire_Rule) * count);
    if (rule_array == NULL)
    {
        shared_print("Error: failed to allocate array size");
        return NULL;
    }
    // Skip leading whitespace
    while (isspace(*p))
        p++;

    // Ensure the string starts with '['
    if (*p != '[')
    {
        shared_print("Error: Input doesn't start with '['");
        shared_free(rule_array);
        return NULL;
    }
    p++;

    // Parse each JSON object
    while (*p)
    {
        // Skip whitespace
        while (isspace(*p))
            p++;

        if (*p == ']')
        {
            // End of list
            break;
        }

        if (*p != '{')
        {
            shared_print("Error: Expected '{' at position %ld", p - input);
            shared_free(rule_array);
            return NULL;
        }

        // Find the end of this JSON object
        char *end = p + 1;
        int brace_count = 1;
        while (*end && brace_count > 0)
        {
            if (*end == '{')
                brace_count++;
            if (*end == '}')
                brace_count--;
            end++;
        }

        if (brace_count != 0)
        {
            shared_print("Error: Unmatched braces");
            shared_free(rule_array);
            return NULL;
        }

        // Copy this JSON object to a new string
        size_t obj_len = end - p;
        char *obj = shared_malloc(obj_len + 1);
        if (obj == NULL)
        {
            shared_print("Error: Memory allocation failed");
            shared_free(rule_array);
            return NULL;
        }
        strncpy(obj, p, obj_len);
        obj[obj_len] = '\0';

        // Process this JSON object
        fire_Rule rule = parse_json_to_rule(obj);

        // shared_free the memory
        shared_free(obj);

        if (rule.id < 0) // error here
        {
            shared_free(rule_array);
            shared_print("Error: Input with rule id parsing%d", rule.id);
            return NULL;
        }

        rule_array[rule_index] = rule;
        rule_index++;
        // Move to the next object
        p = end;

        // Skip whitespace
        while (isspace(*p))
            p++;

        // Check for comma or end of list
        if (*p == ',')
        {
            p++;
        }
        else if (*p != ']')
        {
            shared_print("Error: Expected ',' or ']' at position %ld", p - input);
            shared_free(rule_array);
            return NULL;
        }
    }

    // Ensure the string ends with ']'
    if (*p != ']')
    {
        shared_print("Error: Input doesn't end with ']'");
        shared_free(rule_array);
        return NULL;
    }

    // Skip trailing whitespace
    p++;
    while (isspace(*p))
        p++;

    // Ensure we've reached the end of the string
    if (*p != '\0')
    {
        shared_print("Error: Unexpected characters after closing ']'");
        shared_free(rule_array);
        return NULL;
    }

    shared_print("Parsing completed successfully");
    return rule_array;
}

fire_Rule parse_json_to_rule(char *json_string)
{
    int parse_error = 0;
    fire_Rule rule;

    char *value;
    // Parse id
    value = extract_value(json_string, "id");
    if (value)
    {
        rule.id = parse_int(value);
        shared_free(value);
        if (rule.id < 0)
        {
            shared_print("error parsing id");
            return rule;
        }
    }

    // Parse source_address
    value = extract_value(json_string, "source_address");
    if (value)
    {
        parse_error = parse_ip(value, rule.source_addresses);
        shared_free(value);
        if (parse_error == -1)
        {
            rule.id = -1;
            shared_print("error parsing source ip range");
            return rule;
        }
    }

    // Parse source_port
    value = extract_value(json_string, "source_port");
    if (value)
    {
        rule.source_port = parse_port_range(value);
        shared_free(value);
        if (rule.source_port == -1)
        {
            rule.id = -1;
            shared_print("error parsing source port");
            return rule;
        }
    }

    // Parse destination_address
    value = extract_value(json_string, "destination_address");
    if (value)
    {
        parse_ip(value, rule.destination_addresses);
        shared_free(value);
        if (parse_error == -1)
        {
            rule.id = -1;
            shared_print("error parsing dest ip address range");
            return rule;
        }
    }

    // Parse destination_port
    value = extract_value(json_string, "destination_port");
    if (value)
    {
        rule.destination_port = parse_port_range(value);
        shared_free(value);
        if (rule.destination_port == -1)
        {
            rule.id = -1;
            shared_print("error parsing dest port address range");
            return rule;
        }
    }

    // Parse protocol
    value = extract_value(json_string, "protocol");
    if (value)
    {
        if (strcmp(value, "TCP") == 0)
            rule.proto = fire_proto_TCP;
        else if (strcmp(value, "UDP") == 0)
            rule.proto = fire_proto_UDP;
        else if (strcmp(value, "ANY") == 0)
            rule.proto = fire_proto_ANY;
        else
        {
            rule.id = -1;
            shared_free(value);
            shared_print("error parsing protocol");
            return rule;
        }
        shared_free(value);
    }

    // Parse action
    value = extract_value(json_string, "action");
    if (value)
    {
        if (strcmp(value, "ACCEPT") == 0)
            rule.action = fire_ACCEPT;
        else if (strcmp(value, "DROP") == 0)
            rule.action = fire_DROP;
        else
        {
            rule.id = -1;
            shared_free(value);
            shared_print("error parsing action");
            return rule;
        }
        shared_free(value);
    }

    // Parse direction
    value = extract_value(json_string, "direction");
    if (value)
    {
        if (strcmp(value, "INBOUND") == 0)
            rule.direction = fire_dir_INBOUND;
        else if (strcmp(value, "OUTBOUND") == 0)
            rule.direction = fire_dir_OUTBOUND;
        else
        {
            rule.id = -1;
            shared_free(value);
            shared_print("error parsing diraction");
            return rule;
        }
        shared_free(value);
    }

    // Parse enabled
    value = extract_value(json_string, "enabled");
    if (value)
    {
        if (strcmp(value, "true") == 0)
            rule.enabled = fire_TRUE;
        else if (strcmp(value, "false") == 0)
            rule.enabled = fire_FALSE;
        else
        {
            rule.id = -1;
            shared_free(value);
            shared_print("error parsing enabled ");
            return rule;
        }
    }

    return rule;
}