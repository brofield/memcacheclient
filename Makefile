CC=g++
CFLAGS=-Wall
CPPFLAGS=-Wall
LIBS=-lrt

OBJS=MemCacheClientTest.o MemCacheClient.o ReadWriteBuffer.o Socket.o Matilda.o sha1.o

all: $(OBJS)
	$(CC) -o MemCacheClientTest $(OBJS) $(LIBS)

clean:
	rm -f core *.o MemCacheClientTest

install:
	@echo No install provided. Include the source files in your project.

MemCacheClientTest.o : MemCacheClientTest.cpp
MemCacheClient.o : MemCacheClient.cpp MemCacheClient.h
ReadWriteBuffer.o : ReadWriteBuffer.cpp ReadWriteBuffer.h
md5.o : md5.c md5.h
