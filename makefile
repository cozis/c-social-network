
CC = gcc
CFLAGS = -Wall -Wextra

.PHONY: all

all: serve

sqlite3.o: sqlite3.c sqlite3.h
	$(CC) -c sqlite3.c -o sqlite3.o $(CFLAGS)

serve: serve.c sqlite3.o xhttp.c xhttp.h
	$(CC) serve.c xhttp.c xh_utils.c sqlite3.o -o serve $(CFLAGS)