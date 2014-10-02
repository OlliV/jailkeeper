CC = gcc
CCFLAGS = -Wall -DDEBUG

SRC = jailkeeper.c bpf-helper.c checker.c rules.c

all: jailkeeper

jailkeeper: $(SRC)
	@echo "CC $@"
	@$(CC) $(CCFLAGS) $(SRC) -o $@

.PHONY: all clean

clean:
	rm -f *.o
	rm jailkeeper
