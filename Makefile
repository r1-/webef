LDFLAGS= -lpthread -D_REENTRANT -lssl 
CFLAGS= -g -Wall -D_GNU_SOURCE -I includes -I mods -z relro -z now
SRC=main.c options.c fuzz.c file.c send.c ssl.c http.c encodage.c mods/inject.c
EXEC= webef
OBJS= $(SRC:.c=.o)

#pour prendre tous les .c
#SRC= $(wildcard *.c)

all: $(EXEC) 

$(EXEC): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ -lcrypto
#	rm -f $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	rm -f $(OBJS)
	rm -rf ./docs/$(EXEC).1.gz

mrproper:
	rm -f $(EXEC)

install: $(EXEC)
	install -s -m 755 -o root -- ./$(EXEC) /usr/bin/
	gzip -c ./docs/$(EXEC).1 >> ./docs/$(EXEC).1.gz
	install -m 644 -o root -- ./docs/$(EXEC).1.gz /usr/share/man/man1/


uninstall: clean
	rm -fr /usr/bin/$(EXEC) 
	rm /usr/share/man/man1/$(EXEC).1.gz
