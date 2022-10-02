INCLUDE_DIRS = 
LIB_DIRS = 
CROSS_COMPILE=
CC=$(CROSS_COMPILE)gcc

CDEFS=
CFLAGS= -O0 -g $(INCLUDE_DIRS) $(CDEFS)
LIBS= 

HFILES= 
CFILES= aesdsocket.c

SRCS= ${HFILES} ${CFILES}
OBJS= ${CFILES:.c=.o}

all:	aesdsocket

clean:
	-rm -f *.o *.d
	-rm -f aesdsocket

writer: aesdsocket.o
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $@.o

depend:

.c.o:
	$(CC) $(CFLAGS) -c $<
