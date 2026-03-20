CC ?= gcc
CFLAGS ?= -O2 -g -Wall -Wextra
LDFLAGS ?=
LDLIBS ?= -lbpf -lelf -lz

TARGET := loader mapctl
SRC := loader.c mapctl.c

.PHONY: all clean

all: $(TARGET)

loader: loader.c
	$(CC) $(CFLAGS) loader.c -o loader $(LDFLAGS) $(LDLIBS)

mapctl: mapctl.c
	$(CC) $(CFLAGS) mapctl.c -o mapctl $(LDFLAGS) $(LDLIBS)

clean:
	rm -f $(TARGET)
