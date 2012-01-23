CC=g++
CFLAGS=-Wall
CPPFLAGS=-Wall

OBJS=TestMemCacheClient.o MemCacheClient.o ReadWriteBuffer.o Socket.o Matilda.o sha1.o

all: $(OBJS)
	$(CC) -o TestMemCacheClient $(OBJS)

clean:
	rm -f core *.o TestMemCacheClient

install:
	@echo No install provided. Include the source files in your project.

TestMemCacheClient.o : TestMemCacheClient.cpp
MemCacheClient.o : MemCacheClient.cpp MemCacheClient.h
ReadWriteBuffer.o : ReadWriteBuffer.cpp ReadWriteBuffer.h
md5.o : md5.c md5.h
