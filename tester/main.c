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

    rule_count=test_rule_parse1();
    
        return 0;
}
