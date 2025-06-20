CC=gcc
CFLAGS=-Wall -Wextra -O2
LDFLAGS=-ljansson
TARGET=netre

all: $(TARGET)

$(TARGET): netre.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
