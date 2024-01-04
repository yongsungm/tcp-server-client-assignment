all: client

client.o: client.c
	gcc -ansi -pedantic-errors -Wall -c client.c

client: client.o
	gcc -o client client.o
