CC=g++
CFLAGS=-std=c++11
LIBS=-pthread

all: server client

server: server.cpp
	$(CC) $(CFLAGS) $(LIBS) server.cpp -o server -lssl -lcrypto

client: client.cpp
	$(CC) $(CFLAGS) client.cpp -o client -lssl -lcrypto

clean:
	rm -f server client .usr_pass