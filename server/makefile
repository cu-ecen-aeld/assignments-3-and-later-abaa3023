#native compiler
ifeq ($(CC),)
	CC=$(CROSSCOMPILE)gcc
endif

#compilation flags
ifeq ($(CFLAGS),)
	CFLAGS=-I -g -Wall -Werror
endif

ifeq ($(LDFLAGS),)
	LDFLAGS= -pthread -lrt
endif

all: aesdsocket

default: aesdsocket

aesdsocket: aesdsocket.c
	$(CC) $(CFLAGS) $^ -o $@ $(INCLUDES) $(LDFLAGS)
			
exec=aesdsocket

.PHONY: clean
clean:
		rm -f $(exec) *.o
