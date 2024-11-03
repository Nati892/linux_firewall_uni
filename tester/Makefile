# Compiler
CC = gcc

# Compiler flags
CFLAGS = -Wall -Werror -g

# Target executable name
TARGET = tests

# Rule to build the executable
all: $(TARGET)

# Rule to link the object files and create the executable
$(TARGET): main.o rule_tests.o ../Rule/RuleParser.o
	$(CC) -o $(TARGET) main.o rule_tests.o ../Rule/RuleParser.o ../Head/stdafx.o

# Rule to compile the main.c source file
main.o: main.c rule_tests.h
	$(CC) $(CFLAGS) -c main.c

# Rule to compile the rule_tests.c source file
rule_tests.o: rule_tests.c rule_tests.h stdafx.o
	$(CC) $(CFLAGS) -c rule_tests.c

RuleParser.o: ../Rule/RuleParser.o stdafx.o ../Rule/RuleParser.h ../Rule/Rule.h
	$(CC) $(CFLAGS) -c ../Rule/RuleParser.c 

stdafx.o: ../Head/stdafx.o ../Head/stdafx.h ../Head/stdafx.c
	$(CC) $(CFLAGS) -c ../Head/stdafx.c
	
# Clean up build files
clean:
	rm -f $(TARGET) *.o tests
