CFLAGS += -g -W -Wall -Wno-deprecated-declarations `curl-config --cflags`

OBJS = netproc.o main.o keyproc.o acctproc.o dbg.o base64.o util.o chngproc.o json.o certproc.o

letskencrypt: $(OBJS)
	$(CC) -o $@ $(OBJS) -lssl -lcrypto `curl-config --libs` -ljson-c

install: letskencrypt
	mkdir -p $(PREFIX)/bin
	mkdir -p $(PREFIX)/man/man1
	install -m 0755 letskencrypt $(PREFIX)/bin
	install -m 0644 letskencrypt.1 $(PREFIX)/man/man1

$(OBJS): extern.h

clean:
	rm -f letskencrypt $(OBJS)
	rm -rf letskencrypt.dSYM
