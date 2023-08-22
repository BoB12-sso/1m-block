CC=g++
CFLAGS=-Wall
LIBS=-lnetfilter_queue
TARGET=1m-block

all: $(TARGET)

$(TARGET): 1m-block.o
	$(CC) $(CFLAGS) -o $(TARGET) 1m-block.o $(LIBS)

1m-block.o: 1m-block.cpp
	$(CC) $(CFLAGS) -c 1m-block.cpp

.PHONY: clean

clean:
	rm -f *.o $(TARGET)
