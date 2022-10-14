INCLUDE_DIRS = 
LIB_DIRS = 
CROSS_COMPILE=
CC=$(CROSS_COMPILE)gcc

CDEFS=
CFLAGS= -O0 -g $(INCLUDE_DIRS) $(CDEFS)
LIBS= 

HFILES= 
CFILES= writer.c

SRCS= ${HFILES} ${CFILES}
OBJS= ${CFILES:.c=.o}

all:	writer

clean:
	-rm -f *.o *.d
	-rm -f writer

writer: writer.o
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $@.o

depend:

.c.o:
	$(CC) $(CFLAGS) -c $<

