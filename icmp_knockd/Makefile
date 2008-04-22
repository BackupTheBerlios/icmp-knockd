# Makefile
CC = gcc
LD = gcc
RM = /bin/rm -f  
CFLAGS = -O2 -Wall
LIBS =
OBJS1 = icmp_knockd.o principal.o agent.o client.o netcom.o filter.o util.o log.o sha2.o
PROG1 = icmp_knockd
OBJS2 = icmp_knock.o sha2.o
PROG2 = icmp_knock


all: $(PROG1) $(PROG2)
$(PROG1): $(OBJS1)
	$(CC) -o $(PROG1) $(CFLAGS) $(OBJS1) $(LIBS)
$(PROG2): $(OBJS2)
	$(CC) -o $(PROG2) $(CFLAGS) $(OBJS2) $(LIBS)

%.o: %.c
	$(CC) $(CFALGS) -c $<

install:
	install -m 0500 icmp_knockd /usr/local/sbin
	install -m 0500 icmp_knock /usr/local/sbin
	install -m 0600 doc/icmp_knockd.conf /usr/local/etc
clean:
	$(RM) $(PROG1) $(OBJS1)
	$(RM) $(PROG2) $(OBJS2)
