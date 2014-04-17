OBJS = ptrace temps timetravel
CC = gcc 
CFLAGS = -Wall -g

all : $(OBJS)

ptrace : ptrace.c ptrace.h
	gcc -o ptrace ptrace.c

temps : temps.c
	gcc -o temps temps.c

timetravel : timetravel.c
	gcc -o timetravel timetravel.c -lm

clean:
	rm $(OBJS)
