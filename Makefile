CFLAGS += -g -W -Wall -Wno-deprecated-declarations `curl-config --cflags`

OBJS = netproc.o main.o keyproc.o acctproc.o dbg.o base64.o util.o chngproc.o

letskencrypt: $(OBJS)
	$(CC) -o $@ $(OBJS) -lssl -lcrypto `curl-config --libs` -ljson-c

$(OBJS): extern.h

clean:
	rm -f letskencrypt
	rm -f $(OBJS)
	rm -rf letskencrypt.dSYM
