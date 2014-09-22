OBJS = temps timetravel
CC = gcc 
CFLAGS = -Wall -g

all : $(OBJS)

temps : temps.c
	gcc -o temps temps.c

timetravel : timetravel.c
	gcc -o timetravel timetravel.c -lm

clean:
	rm $(OBJS)
