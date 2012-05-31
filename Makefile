OBJS = args_trace.o syscalls_io.o calc_times_proc.o times_proc.o peek_data.o sockets.o insert_trace.o run_trace.o

CFLAGS = -Wall -g 
CC=gcc

all : $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) -o run_trace

-include .depend

# create the dependency file
.depend: ${wildcard *.c}
	$(CC) -MM $(CFLAGS) $^ > $@

launcher: launcher.c
	$(CC) $(LDFLAGS) $(CFLAGS) -o launcher launcher.c

clean:
	rm -rf run_trace $(OBJS)

