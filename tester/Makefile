# Compiler
CC = gcc
# Compiler flags with PIE support
CFLAGS = -Wall -Werror -g -fPIE
# Linker flags
LDFLAGS = -pie
# Target executable name
TARGET = tests

# Rule to build the executable
all: $(TARGET)

# Rule to link the object files and create the executable
$(TARGET): main.o rule_tests.o ../Rule/RuleParser.o ../Head/stdafx.o
	$(CC) $(LDFLAGS) -o $(TARGET) $^

# Rule to compile the main.c source file
main.o: main.c rule_tests.h
	$(CC) $(CFLAGS) -c main.c

# Rule to compile the rule_tests.c source file
rule_tests.o: rule_tests.c rule_tests.h stdafx.o
	$(CC) $(CFLAGS) -c rule_tests.c

RuleParser.o: ../Rule/RuleParser.c ../Rule/RuleParser.h ../Rule/Rule.h
	$(CC) $(CFLAGS) -c ../Rule/RuleParser.c 

stdafx.o: ../Head/stdafx.c ../Head/stdafx.h
	$(CC) $(CFLAGS) -c ../Head/stdafx.c
	
# Clean up build files
clean:
	rm -f $(TARGET) *.o tests
