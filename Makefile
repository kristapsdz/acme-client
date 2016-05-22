PREFIX	 = /usr/local
CFLAGS	+= -g -W -Wall -Wno-deprecated-declarations `curl-config --cflags`
OBJS 	 = acctproc.o \
	   base64.o \
	   certproc.o \
	   chngproc.o \
	   dbg.o \
	   dnsproc.o \
	   fileproc.o \
	   jsmn.o \
	   json.o \
	   keyproc.o \
	   main.o \
	   netproc.o \
	   revokeproc.o \
	   sandbox-pledge.o \
	   util.o

letskencrypt: $(OBJS)
	$(CC) -o $@ $(OBJS) -lssl -lcrypto `curl-config --libs` 

jsmn.o json.o: jsmn.h

install: letskencrypt
	mkdir -p $(PREFIX)/bin
	mkdir -p $(PREFIX)/man/man1
	install -m 0755 letskencrypt $(PREFIX)/bin
	install -m 0644 letskencrypt.1 $(PREFIX)/man/man1

$(OBJS): extern.h

clean:
	rm -f letskencrypt $(OBJS)
