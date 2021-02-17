#
# Makefile for pcap2arrow
#
OBJS = pcap2arrow.o arrow_nodes.o arrow_write.o
PROG = pcap2arrow
LIBS = -lpthread -lpfring -lpcap 
CFLAGS = -O2 -g -Wall -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64
#CFLAGS += -O0

PREFIX := /usr/local

all: $(PROG)

$(PROG): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LIBS)

.c.o:
	$(CC) $(CFLAGS) -c -o $@ $<

install: $(PROG)
	install -m 0755 $(PROG) $(PREFIX)/bin

clean:
	rm -f $(PROG) $(OBJS)
