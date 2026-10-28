CC ?= gcc
CFLAGS ?= -Wall -Wextra -std=c11 -D_GNU_SOURCE
FUSE_CFLAGS = $(shell pkg-config --cflags fuse3 2>/dev/null || echo "-I/usr/include/fuse3")
FUSE_LIBS   = $(shell pkg-config --libs fuse3 2>/dev/null || echo "-lfuse3") -lssl -lcrypto -lpthread -lm

SRCS = src/main.c src/crypto.c src/storage.c src/inode.c src/snapshot.c src/fuse_ops.c src/entropy.c
OBJS = $(SRCS:.c=.o)

TARGET = vaultfs
CTL_TARGET = vaultfs-ctl

all: $(TARGET) $(CTL_TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(FUSE_LIBS)

src/%.o: src/%.c
	$(CC) $(CFLAGS) $(FUSE_CFLAGS) -c -o $@ $<

$(CTL_TARGET): tools/vaultfs_ctl.c
	$(CC) $(CFLAGS) -o $@ $< -lm

clean:
	rm -f src/*.o tools/*.o $(TARGET) $(CTL_TARGET)
	rm -rf /tmp/vaultfs_*

docker-build:
	docker build -t vaultfs .

docker-run:
	docker run --privileged --rm -it vaultfs

.PHONY: all clean docker-build docker-run
