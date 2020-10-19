DEBUG_CFLAGS=-g -O0
CFLAGS=-std=gnu99 $(DEBUG_CFLAGS)
LDFLAGS=-lroaring -lpcap
CC=gcc
all: 
	make main
main.o:
	$(CC) $(CFLAGS) $(LDFLAGS) main.c -c -o main.o
main: main.o
	$(CC) $(CFLAGS) $(LDFLAGS) main.o -o main


clean:
	@rm -rf main.o main
.PHONY: *.o all clean
	
