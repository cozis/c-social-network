
CC = gcc
CFLAGS = -Wall -Wextra -DDEBUG -g

.PHONY: all

all: serve

sqlite3.o: src/3p/sqlite3.c src/3p/sqlite3.h
	$(CC) -c src/3p/sqlite3.c -o sqlite3.o $(CFLAGS)

serve: $(wildcard src/*.h src/*.c src/util/*.h src/util/*.c) sqlite3.o src/3p/xhttp.c src/3p/xhttp.h src/3p/xh_utils.c src/3p/xh_utils.h
	$(CC) $(wildcard src/*.c) $(wildcard src/util/*.c) src/3p/xhttp.c src/3p/xh_utils.c sqlite3.o -o serve $(CFLAGS)
