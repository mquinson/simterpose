OBJS = ptrace temps
CC = gcc 
CFLAGS = -Wall -g

all : $(OBJS)

ptrace : ptrace.c ptrace.h
	gcc -o ptrace ptrace.c

temps : temps.c
	gcc -o temps temps.c

clean:
	rm $(OBJS)
