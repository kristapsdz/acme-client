CFLAGS	+= -g -W -Wall -Wno-deprecated-declarations `curl-config --cflags`
OBJS 	 = acctproc.o \
	   base64.o \
	   certproc.o \
	   chngproc.o \
	   dbg.o \
	   dnsproc.o \
	   fileproc.o \
	   json.o \
	   keyproc.o \
	   main.o \
	   netproc.o \
	   util.o

# On non-Linux (Mac OS X, BSD):
LIBJSON	 = -ljson-c

# On Linux:
#LIBJSON = -ljson
#LIBBSD	 = -lbsd

letskencrypt: $(OBJS)
	$(CC) -o $@ $(OBJS) -lssl -lcrypto `curl-config --libs` $(LIBJSON) $(LIBBSD)

install: letskencrypt
	mkdir -p $(PREFIX)/bin
	mkdir -p $(PREFIX)/man/man1
	install -m 0755 letskencrypt $(PREFIX)/bin
	install -m 0644 letskencrypt.1 $(PREFIX)/man/man1

$(OBJS): extern.h

clean:
	rm -f letskencrypt $(OBJS)
	rm -rf letskencrypt.dSYM
