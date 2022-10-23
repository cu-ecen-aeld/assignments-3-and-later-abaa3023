#Makefile for the writer application
#For cross compilation use the below mentioned command
#make writer CROSS_COMPILE=<cross_compiler version>

#native compiler
CC=gcc

#compilation flags
CFLAGS=-I -g -Wall -Werror

all: writer

writer: writer.o
	$(CROSS_COMPILE)$(CC) $(CFLAGS) writer.c -o writer
	
exec = writer

.PHONY: clean
clean:
	rm -f $(exec) *.o
