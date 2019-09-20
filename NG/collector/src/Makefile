CC = gcc
CFLAGS = -g -O3 -Wall -lpthread -I../slog 
LIB = ../slog/libslog.a
OBJ = njmonNG_collector_v31.o
INSTALL = ../bin

all: $(OBJ)
	$(CC) $(CFLAGS) -o njmonNG_collector_v31 $(OBJ) $(LIB)
	@echo [-] Building binaries into - $(INSTALL)
	@test -d $(INSTALL) || mkdir $(INSTALL)
	@install -m 0755 njmonNG_collector_v31 $(INSTALL)/
	@install -m 0664 slog.cfg $(INSTALL)/
	@echo [-] Executable files built in - $(INSTALL) folder

.PHONY: clean

clean:
	$(RM) njmonNG_collector_v31 $(OBJ)
		
