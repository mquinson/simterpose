all:    libs programme

programme: programme.o
	gcc -o programme programme.o 

programme.o: programme.c 
	gcc -o programme.o -c programme.c -W -Wall -ansi -lc

libs:   libs.so

libs.so:	lib.c
	gcc -fPIC -shared -Wl,-soname,libs.so -ldl -o libs.so lib.c 

clean:
	rm -f libs.so* programme *.o
