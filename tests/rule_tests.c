#include "rule_tests.h"

int test_rule_count1()
{
    return GetRuleCount("{}{}{}",6);
    return 1;
}

int test_rule_count2()
{
    return GetRuleCount("{}{}{}{}{}",10);
    return 1;
}