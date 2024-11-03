#include "main.h"
int main(int argc, char **argv)
{
    return RunTests();
}
int RunTests()
{
    shared_print("!!!!!3");
    fire_BOOL fully_passed = fire_TRUE;
    shared_print("tests start");
    shared_print("~~test1 Started");
    int rule_count = parse_test1();
    if (rule_count > 0)
    {
        shared_print("~~test1 PASSED %d", rule_count);
    }
    else
    {
        shared_print("~~test1 FAILED");
        fully_passed = fire_FALSE;
    }
    shared_print("~~test2 Started");
    rule_count = parse_test2();
    if (rule_count > 0)
    {
        shared_print("~~test2 PASSED %d", rule_count);
    }
    else
    {
        shared_print("~~test2 FAILED");
        fully_passed = fire_FALSE;
    }

    shared_print("~~test3 Started");
    rule_count = parse_test3();
    if (rule_count > 0)
    {
        shared_print("~~test3 PASSED %d", rule_count);
    }
    else
    {
        shared_print("~~test3 FAILED");
        fully_passed = fire_FALSE;
    }

    shared_print("~~test4 Started");
    rule_count = parse_test4();
    if (rule_count > 0)
    {
        shared_print("~~test4 PASSED %d", rule_count);
    }
    else
    {
        shared_print("~~test4 FAILED");
        fully_passed = fire_FALSE;
    }

    shared_print("~~test5 Started");
    rule_count = parse_test5();
    if (rule_count > 0)
    {
        shared_print("~~test5 PASSED %d", rule_count);
    }
    else
    {
        shared_print("~~test5 FAILED! ");
        fully_passed = fire_FALSE;
    }

    shared_print("~~test6 Started");
    rule_count = parse_test6();
    if (rule_count > 0)
    {
        shared_print("~~test6 PASSED %d", rule_count);
    }
    else
    {
        shared_print("test6 FAILED! ");
        fully_passed = fire_FALSE;
    }

    shared_print("~~test7 Started");
    rule_count = parse_test7();
    if (rule_count > 0)
    {
        shared_print("~~test7 PASSED %d", rule_count);
    }
    else
    {
        shared_print("~~test7 FAILED! ");
        fully_passed = fire_FALSE;
    }
    if (fully_passed == fire_TRUE)
    {
        shared_print("All tests PASSED!");
        return 0;
    }
    else
    {
        shared_print("Some tests FAILED!");
        return 1;
    }
    return 0;
}
