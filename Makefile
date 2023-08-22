CC=gcc
CFLAGS=-Wall
LIBS=-lnetfilter_queue
TARGET=netfilter-test

all: $(TARGET)

$(TARGET): netfilter-test.o
	$(CC) $(CFLAGS) -o $(TARGET) netfilter-test.o $(LIBS)

netfilter-test.o: netfilter-test.c
	$(CC) $(CFLAGS) -c netfilter-test.c

.PHONY: clean

clean:
	rm -f *.o $(TARGET)
