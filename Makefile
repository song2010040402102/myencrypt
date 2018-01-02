# makefile for myencrypt

all: myencrypt

#compiler
CC = gcc

#compiler flags for development
#CFLAGS = -g -Wall -ansi
#CFLAGS = -g -D_FILE_OFFSET_BITS=64

#compiler flags for release
#CFLAGS = -O -Wall -ansi
CFLAGS = -O -D_FILE_OFFSET_BITS=64

#include directory
INCLUDE = .

myencrypt: main.o
	$(CC) -o myencrypt main.o -lreadline -ltermcap

main.o: main.c
	$(CC) -I$(INCLUDE) $(CFLAGS) -c main.c

clean: 
	rm *.o

#install directory
INSTALL = /usr/local/bin
	
install: myencrypt
	@if [ -d $(INSTALL) ]; then \
		cp myencrypt $(INSTALL)/myencrypt &&\
		chmod a+x $(INSTALL)/myencrypt &&\
		chmod go-w $(INSTALL)/myencrypt &&\
		echo "installed in $(INSTALL)"; \
	else \
		echo "$(INSTALL) not existed"; \
	fi	

	@gzip -c myencrypt.1 > myencrypt.1.gz
	@mv myencrypt.1.gz /usr/share/man/man1

