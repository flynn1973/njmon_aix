CFLAGS= -maix64 -g -Wl,-b64
LDFLAGS=-lperfstat

VERSION=v33
FILE=njmonNG_aix_$(VERSION).c



njmonNG_aix71: $(FILE)
	gcc $(CFLAGS) -o $@_$(VERSION) $(FILE) $(LDFLAGS)

clean:
	rm -f njmonNG_aix71_$(VERSION) 
