OBJS = args_trace.o syscalls_io.o calc_times_proc.o times_proc.o peek_data.o sockets.o insert_trace.o run_trace.o benchmark.o

CFLAGS = -Wall -g 
CC=gcc

LDFLAGS= -lsimgrid

all : $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) -o run_trace

-include .depend

# create the dependency file
.depend: ${wildcard *.c}
	$(CC) -MM $(CFLAGS) $^ > $@

launcher: launcher.c
	$(CC) $(LDFLAGS) $(CFLAGS) -o launcher launcher.c

replay: replay.c
	$(CC) $(LDFLAGS) $(CFLAGS) -o replay replay.c
clean:
	rm -rf run_trace $(OBJS)

benchmark: run_benchmark.c benchmark.c calc_times_proc.o 
	$(CC) $(CFLAGS) -o benchmark run_benchmark.c benchmark.c calc_times_proc.o
