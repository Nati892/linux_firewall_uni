#ifndef RULEPARSER_H
#define RULEPARSER_H

#define MAX_IP_LENGTH 32
#define MAX_PORT_LENGTH 16

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include "Rule.h"

int GetRuleCount(char *in_json, int length);

fire_BOOL ParseRules(char *in_json,
                     int length,
                     fire_Rule **rule_table_inbound, int *table_size_inbound,
                     fire_Rule **rule_table_outbound, int *table_size_outbound);
fire_Rule parse_json_to_rule(char *json_string);
fire_Rule *parse_json_list(char *input, int count);
#endif