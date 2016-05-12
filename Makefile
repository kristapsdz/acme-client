CFLAGS += -g -W -Wall -Wno-deprecated-declarations `curl-config --cflags`

OBJS = netproc.o main.o keyproc.o acctproc.o dbg.o

letskencrypt: $(OBJS)
	$(CC) -o $@ $(OBJS) -lssl -lcrypto `curl-config --libs`

clean:
	rm -f letskencrypt
	rm -f $(OBJS)
	rm -rf letskencrypt.dSYM
