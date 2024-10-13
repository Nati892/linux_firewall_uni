# Compiler
CC = gcc

# Compiler flags
CFLAGS = -Wall -Werror

# Target executable name
TARGET = tests

# Rule to build the executable
all: $(TARGET)

# Rule to link the object files and create the executable
$(TARGET): main.o rule_tests.o RuleParser.o
	$(CC) -o $(TARGET) main.o rule_tests.o RuleParser.o

# Rule to compile the main.c source file
main.o: main.c rule_tests.h
	$(CC) $(CFLAGS) -c main.c

# Rule to compile the rule_tests.c source file
rule_tests.o: rule_tests.c rule_tests.h
	$(CC) $(CFLAGS) -c rule_tests.c

RuleParser.o: ../RuleParser.c ../RuleParser.h ../Rule.h
	$(CC) $(CFLAGS) -c ../RuleParser.c
# Clean up build files
clean:
	rm -f $(TARGET) *.o tests
