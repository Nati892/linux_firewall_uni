#include "RuleParser.h"

int GetRuleCount(char *in_json, int length)
{
    int count = 0;
    int i = 0;

    fire_BOOL in_opening_brackets = proto_FALSE;
    while (*in_json != '\0' && i < length)
    {
        if (*in_json == '{' && in_opening_brackets == proto_FALSE)
        {
            in_opening_brackets = proto_TRUE;
            count++;
        }
        else if (*in_json == '{' && in_opening_brackets == proto_TRUE) // report error
        {
            return -1;
        }

        if (*in_json == '}' && in_opening_brackets == proto_TRUE)
        {
            in_opening_brackets = proto_FALSE;
        }
        else if (*in_json == '}' && in_opening_brackets == proto_FALSE) // report error
        {
            return -1;
        }

        in_json++;
        i++;
    }

    return count;
}

fire_BOOL ParseRules(char *in_json, int length, fire_Rule *rule_table, int table_size)
{
    return proto_FALSE;
}

__uint32_t char_array_to_u32(const char ip[4]) {
    // Combine bytes into a __u32
    return ((__uint32_t)(unsigned char)ip[0] << 24) | 
           ((__uint32_t)(unsigned char)ip[1] << 16) | 
           ((__uint32_t)(unsigned char)ip[2] << 8)  | 
           ((__uint32_t)(unsigned char)ip[3]);
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

// Helper function to parse a single integer
int parse_int(const char *str)
{
    char *endptr;
    errno = 0;
    long val = strtol(str, &endptr, 10);

    if (errno != 0 || endptr == str || *endptr != '\0' || val > INT_MAX || val < INT_MIN)
    {
        printf("error parsing int");
        return -1; // Return 0 on error
    }

    return (int)val;
}

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
            if (res < 0 || res > 65535)
            {
                free(rest);
                return -1;
            }
            if (res < -1)
            {
                free(rest);
                return -1;
            }
            output[i]=(char)res;
        }
        i++;
    }

    free(rest);
    return 0;
}

// Helper function to parse IP address range
int parse_ip_range(const char *ip_range, char* output)
{
    char start_ip[MAX_IP_LENGTH], end_ip[MAX_IP_LENGTH];
    const char *delimiter = strchr(ip_range, '-');

    if (delimiter)
    {
        size_t start_len = delimiter - ip_range;
        safe_strcpy(start_ip, sizeof(start_ip), ip_range);
        start_ip[start_len] = '\0';
        safe_strcpy(end_ip, sizeof(end_ip), delimiter + 1);
    }
    else
    {
        safe_strcpy(start_ip, sizeof(start_ip), ip_range);
        safe_strcpy(end_ip, sizeof(end_ip), ip_range);
    }

    if (parse_ip(start_ip, output) == -1 || parse_ip(end_ip, output + 4) == -1)
    {
        return -1;
    }

    return 0;
}

// Helper function to parse port range
int parse_port_range(const char *port_range)
{
    char start_port[MAX_PORT_LENGTH], end_port[MAX_PORT_LENGTH];
    const char *delimiter = strchr(port_range, '-');

    if (delimiter)
    {
        size_t start_len = delimiter - port_range;
        safe_strcpy(start_port, sizeof(start_port), port_range);
        start_port[start_len] = '\0';
        safe_strcpy(end_port, sizeof(end_port), delimiter + 1);
    }
    else
    {
        safe_strcpy(start_port, sizeof(start_port), port_range);
        safe_strcpy(end_port, sizeof(end_port), port_range);
    }

    return parse_int(start_port); // For simplicity, we're just returning the start of the range
}

// Helper function to extract value from JSON string
char *extract_value(const char *json, const char *key)
{
    char search_key[256];
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
    char *value = (char *)malloc(length + 1);
    if (value == NULL)
        return NULL;

    safe_strcpy(value, length + 1, start);
    return value;
}

fire_Rule *parse_json_to_rule(const char *json_string)
{
    int parse_error = 0;
    fire_Rule *rule = (fire_Rule *)malloc(sizeof(fire_Rule));
    if (rule == NULL)
    {
        return NULL;
    }

    char *value;

    // Parse id
    value = extract_value(json_string, "id");
    if (value)
    {
        rule->id = parse_int(value);
        free(value);
        if (rule->id == -1)
        {
            printf("error parsing id");
            free(rule);
            return NULL;
        }
    }

    // Parse source_address
    value = extract_value(json_string, "source_address");
    if (value)
    {
        parse_error = parse_ip_range(value, rule->source_addresses);
        free(value);
        if (parse_error == -1)
        {
            printf("error parsing source ip range");
            free(rule);
            return NULL;
        }
    }

    // Parse source_port
    value = extract_value(json_string, "source_port");
    if (value)
    {
        rule->source_port = parse_port_range(value);
        free(value);
        if (rule->source_port == -1)
        {
            printf("error parsing source port");
            free(rule);
            return NULL;
        }
    }

    // Parse destination_address
    value = extract_value(json_string, "destination_address");
    if (value)
    {
        parse_ip_range(value, rule->destination_addresses);
        free(value);
        if (parse_error == -1)
        {
            printf("error parsing dest ip address range");
            free(rule);
            return NULL;
        }
    }

    // Parse destination_port
    value = extract_value(json_string, "destination_port");
    if (value)
    {
        rule->destination_port = parse_port_range(value);
        free(value);
        if (rule->destination_port == -1)
        {
            free(rule);
            return NULL;
        }
    }

    // Parse protocol
    value = extract_value(json_string, "protocol");
    if (value)
    {
        if (strcmp(value, "TCP") == 0)
            rule->proto = proto_TCP;
        else if (strcmp(value, "UDP") == 0)
            rule->proto = proto_UDP;
        else
        {
            free(value);
            free(rule);
            return NULL;
        }
        free(value);
    }

    // Parse action
    value = extract_value(json_string, "action");
    if (value)
    {
        if (strcmp(value, "ACCEPT") == 0)
            rule->action = proto_ACCEPT;
        else if (strcmp(value, "DROP") == 0)
            rule->action = proto_DROP;
        else
        {
            free(value);
            free(rule);
            return NULL;
        }
        free(value);
    }

    // Parse direction
    value = extract_value(json_string, "direction");
    if (value)
    {
        if (strcmp(value, "INBOUND") == 0)
            rule->direction = proto_INBOUND;
        else if (strcmp(value, "DROP") == 0)
            rule->direction = proto_OUTBOUND;
        else
        {
            free(value);
            free(rule);
            return NULL;
        }
        free(value);
    }

    // Parse enabled
    value = extract_value(json_string, "enabled");
    if (value)
    {
        if (strcmp(value, "true") == 0)
            rule->enabled = proto_TRUE;
        else if (strcmp(value, "false") == 0)
            rule->enabled = proto_FALSE;
        else
        {
            free(value);
            free(rule);
            return NULL;
        }
    }

    return rule;
}
