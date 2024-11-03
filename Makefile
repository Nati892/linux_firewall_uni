PWD := $(CURDIR)

obj-m += firemod.o
obj-y += Rule/RuleParser.o Head/stdafx.o tester/rule_tests.o tester/main.o

firemod-objs := firemod_core.o Rule/RuleParser.o Head/stdafx.o tester/main.o tester/rule_tests.o


all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
