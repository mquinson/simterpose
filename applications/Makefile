OBJS = server client
CC = gcc
CFLAGS = -Wall -g

all : $(OBJS)

server : server.c
	gcc -o server server.c -lpthread

client : client.c
	gcc -o client client.c
