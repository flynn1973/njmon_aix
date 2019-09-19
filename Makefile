CFLAGS= -maix64 -g -Wl,-b64
CFLAGS_LINUX= -g
LDFLAGS=-lperfstat

VERSION=v31
FILE=njmon_aix_$(VERSION).c

njmon_aix723: $(FILE)
	gcc $(CFLAGS) -o $@_$(VERSION) $(FILE) $(LDFLAGS)

njmon_aix722: $(FILE)
	gcc $(CFLAGS) -o $@_$(VERSION) $(FILE) $(LDFLAGS)

njmon_aix71: $(FILE)
	gcc $(CFLAGS) -o $@_$(VERSION) $(FILE) $(LDFLAGS)

njmon_aix61: $(FILE)
	gcc $(CFLAGS) -o $@_$(VERSION) $(FILE) $(LDFLAGS) -D AIX6

njmon_vios2: $(FILE)
	gcc $(CFLAGS) -o $@_$(VERSION) $(FILE) $(LDFLAGS) -D AIX6 -D VIOS -D SSP

njmon_vios3: $(FILE)
	gcc $(CFLAGS) -o $@_$(VERSION) $(FILE) $(LDFLAGS) -D VIOS -D SSP

njmon_collector: njmon_collector.c
	gcc $(CFLAGS_LINUX) -o $@_$(VERSION) $@.c 

clean:
	rm -f njmon_aix723_$(VERSION) njmon_aix722_$(VERSION) njmon_aix71_$(VERSION) njmon_aix61_$(VERSION) njmon_vios2_$(VERSION) njmon_vios3_$(VERSION)
