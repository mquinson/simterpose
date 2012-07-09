OBJS = server client server_select client_select client_simple server_simple server_poll
CC = gcc 
CFLAGS = -Wall -g

all : $(OBJS)

server : server.c
	gcc -o server server.c -lpthread

client : client.c
	gcc -o client client.c

server_select: server_select.c
	gcc -o server_select server_select.c

server_simple: serveur_simple.c
	gcc -o server_simple serveur_simple.c

server_poll: server_poll.c
	gcc -o server_poll server_poll.c

client_select: client_select.c
	gcc -o client_select client_select.c

client_simple: client_simple.c
	gcc -o client_simple client_simple.c
