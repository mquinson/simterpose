all: libpthr a.out

a.out: programme.c 
	gcc -Wall -ggdb programme.c -pthread

libpthr: libpthr.so

libpthr.so:	mdfpthread.c
	gcc -Wall -fpic -shared -ggdb mdfpthread.c -pthread -ldl -o libpthr.so 

clean:
	rm -f libpthr.so* programme *.o *.out
