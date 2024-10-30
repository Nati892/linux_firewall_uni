#include "rule_tests.h"
#include <stdio.h>
int main(int argc, char **argv)
{
    printf("tests start\n");
    int rule_count = test_rule_count1();
    if (rule_count > 0)
    {
        printf("test1 passed %d\n", rule_count);
    }
    else
    {
        printf("pak\n");
        return 1;
    }

    rule_count = test_rule_count2();
    if (rule_count > 0)
    {
        printf("test2 passed %d\n", rule_count);
    }
    else
    {
        printf("pak\n");
        return 1;
    }

    rule_count = test_rules_parse1();
    if (rule_count > 0)
    {
        printf("test3 passed %d\n", rule_count);
    }
    else
    {
        printf("pak\n");
        return 1;
    }

    rule_count = test_rules_parse2();
    if (rule_count > 0)
    {
        printf("test4 passed %d\n", rule_count);
    }
    else
    {
        printf("pak\n");
        return 1;
    }

    rule_count = test_rules_parse3();
    if (rule_count > 0)
    {
        printf("test5 passed %d\n", rule_count);
    }
    else
    {
        printf("pak\n");
        return 1;
    }

  rule_count = test_rules_parse4();
    if (rule_count > 0)
    {
        printf("test6 passed %d\n", rule_count);
    }
    else
    {
        printf("pak\n");
        return 1;
    }


    return 0;
}
