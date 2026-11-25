CC = gcc
CFLAGS = -std=c11 -O2 -Wall -Wextra -Isrc
LDFLAGS = -liphlpapi -lws2_32 -lpsapi -ladvapi32

SRCS = src/main.c src/netinfo.c src/tui.c src/app.c
OBJS = $(SRCS:.c=.o)
TARGET = taskport.exe

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET)
