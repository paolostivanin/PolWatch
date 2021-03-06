CC=clang
CFLAGS = -Wall -Wextra -std=c11 -D_FORTIFY_SOURCE=2 -O2 -Wformat -Wformat-security -fstack-protector-all -fmudflap -lmudflap -fPIE -Wno-unused-result
LDFLAGS = -Wl,-z,now -Wl,-z,relro -lgcrypt -lsqlite3
SOURCES = src/*.c
all: polwatch
polwatch: $(SOURCES)
	$(CC) $(CFLAGS) $(SOURCES) -o polwatch $(LDFLAGS)
	
